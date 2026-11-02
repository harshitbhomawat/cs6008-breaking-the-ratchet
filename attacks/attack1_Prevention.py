RESERVATION_TTL_SECONDS = 30
MAX_ACTIVE_RESERVATIONS_PER_ACCOUNT = 2


def fetch_prekey_bundle(requester, target):
    # Requests must be attributable and rate-limited. Authentication alone is not
    # sufficient because a malicious account can still drain another user's OPKs.
    require_authenticated_account(requester)
    rate_limit(requester.account_id, requester.ip, target)

    # The transaction/row lock makes allocation atomic: concurrent requests can
    # never receive the same one-time prekey.
    with database.transaction():
        expire_old_reservations(target, RESERVATION_TTL_SECONDS)
        if active_reservations(requester.account_id, target) >= \
                MAX_ACTIVE_RESERVATIONS_PER_ACCOUNT:
            raise TooManyReservations()

        opk = select_available_opk_for_update(target)
        if opk is None:
            notify_user_to_replenish(target)
            raise PrekeysTemporarilyUnavailable()

        reservation = reserve(
            opk=opk,
            requester=requester.account_id,
            expires_in=RESERVATION_TTL_SECONDS,
        )

    return public_bundle(target, opk, reservation.token)


def accept_initial_message(sender, receiver, init_header):
    # Bind the reservation to the intended requester and consume it once. An
    # expired or replayed token cannot consume another key.
    with database.transaction():
        reservation = get_reservation_for_update(init_header.reservation_token)
        require(reservation.requester == sender.account_id)
        require(reservation.target == receiver.account_id)
        require(reservation.opk_id == init_header.opk_id)
        require(not reservation.expired and not reservation.consumed)
        reservation.consumed = True
        mark_opk_consumed(reservation.opk_id)

    queue_initial_message(receiver, init_header)

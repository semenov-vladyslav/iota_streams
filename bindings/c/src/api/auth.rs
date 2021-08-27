use super::*;

pub type Author = iota_streams::app_channels::api::tangle::Author<TransportWrap>;

/// Generate a new Author Instance
#[no_mangle]
pub unsafe extern "C" fn auth_new(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_author.as_mut().map_or(Err::NullArgument, |author| {
                let user = Author::new(seed, channel_impl, tsp.clone());
                *author = safe_into_mut_ptr(user);
                Err::Ok
            })
        })
    })
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub unsafe extern "C" fn auth_recover(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    c_ann_address: *const Address,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);
    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        c_ann_address.as_ref().map_or(Err::NullArgument, |addr| {
            transport.as_ref().map_or(Err::NullArgument, |tsp| {
                c_author.as_mut().map_or(Err::NullArgument, |author| {
                    Author::recover(seed, addr, channel_impl, tsp.clone()).map_or_else(operation_failed, |user| {
                        *author = safe_into_mut_ptr(user);
                        Err::Ok
                    })
                })
            })
        })
    })
}

/// Import an Author instance from an encrypted binary array
#[no_mangle]
pub unsafe extern "C" fn auth_import(
    c_author: *mut *mut Author,
    buffer: Buffer,
    c_password: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_author.as_mut().map_or(Err::NullArgument, |author| {
                let bytes_vec: Vec<_> = buffer.into();
                Author::import(&bytes_vec, password, tsp.clone()).map_or_else(operation_failed, |user| {
                    *author = safe_into_mut_ptr(user);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_export(buf: *mut Buffer, c_author: *mut Author, c_password: *const c_char) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        c_author.as_ref().map_or(Err::NullArgument, |user| {
            buf.as_mut().map_or(Err::NullArgument, |buf| {
                user.export(password).map_or_else(operation_failed, |bytes| {
                    *buf = bytes.into();
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub extern "C" fn auth_drop(user: *mut Author) {
    safe_drop_mut_ptr(user)
}

/// Channel app instance.
#[no_mangle]
pub unsafe extern "C" fn auth_channel_address(addr: *mut *const ChannelAddress, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            user.channel_address().map_or(Err::OperationFailed, |channel_address| {
                *addr = channel_address as *const ChannelAddress;
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_is_multi_branching(flag: *mut uint8_t, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        flag.as_mut().map_or(Err::NullArgument, |flag| {
            *flag = if user.is_multi_branching() { 1 } else { 0 };
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_get_public_key(pk: *mut *const PublicKey, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        pk.as_mut().map_or(Err::NullArgument, |pk| {
            *pk = user.get_public_key() as *const PublicKey;
            Err::Ok
        })
    })
}

/// Announce creation of a new Channel.
#[no_mangle]
pub unsafe extern "C" fn auth_send_announce(addr: *mut *const Address, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            user.send_announce().map_or_else(operation_failed, |a| {
                *addr = safe_into_ptr(a);
                Err::Ok
            })
        })
    })
}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub unsafe extern "C" fn auth_receive_subscribe(user: *mut Author, link: *const Address) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            user.receive_subscribe(link).map_or_else(operation_failed, |_| Err::Ok)
        })
    })
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: *const Address,
    psk_ids: *const PskIds,
    ke_pks: *const KePks,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                psk_ids.as_ref().map_or(Err::NullArgument, |psk_ids| {
                    ke_pks.as_ref().map_or(Err::NullArgument, |ke_pks| {
                        let mut identifiers: Vec<Identifier> = psk_ids.iter().map(|pskid| (*pskid).into()).collect();
                        identifiers.append(&mut ke_pks.iter().map(|pk| (*pk).into()).collect());
                        user.send_keyload(link_to, &identifiers[..])
                            .map_or_else(operation_failed, |response| {
                                *r = response.into();
                                Err::Ok
                            })
                    })
                })
            })
        })
    })
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload_for_everyone(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                user.send_keyload_for_everyone(link_to)
                    .map_or_else(operation_failed, |response| {
                        *r = response.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(Err::NullArgument, |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let e = user
                        .send_tagged_packet(link_to, &public_payload, &masked_payload)
                        .map_or_else(operation_failed, |response| {
                            *r = response.into();
                            Err::Ok
                        });
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    e
                })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_tagged_packet(
    r: *mut PacketPayloads,
    user: *mut Author,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_tagged_packet(link)
                    .map_or_else(operation_failed, |tagged_payloads| {
                        *r = tagged_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(Err::NullArgument, |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let e = user
                        .send_signed_packet(link_to, &public_payload, &masked_payload)
                        .map_or_else(operation_failed, |response| {
                            *r = response.into();
                            Err::Ok
                        });
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    e
                })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_signed_packet(
    r: *mut PacketPayloads,
    user: *mut Author,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_signed_packet(link)
                    .map_or_else(operation_failed, |signed_payloads| {
                        *r = signed_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_sequence(r: *mut *const Address, user: *mut Author, link: *const Address) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_sequence(link).map_or_else(operation_failed, |seq_link| {
                    *r = safe_into_ptr(seq_link);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_gen_next_msg_ids(ids: *mut *const NextMsgIds, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        ids.as_mut().map_or(Err::NullArgument, |ids| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            *ids = safe_into_ptr(next_msg_ids);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_msg(
    r: *mut *const UnwrappedMessage,
    user: *mut Author,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_msg(link).map_or_else(operation_failed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_next_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut Author) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            let msgs = user.fetch_next_msgs();
            *umsgs = safe_into_ptr(msgs);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msg(umsg: *mut *const UnwrappedMessage, user: *mut Author, address: *const Address) -> Err {
    umsg.as_mut().map_or(Err::NullArgument, |umsg| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                user.fetch_prev_msg(addr).map_or_else(operation_failed, |msg| {
                    *umsg = safe_into_ptr(msg);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut Author, address: *const Address, num_msgs: size_t) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                user.fetch_prev_msgs(addr, num_msgs).map_or_else(operation_failed, |msgs| {
                    *umsgs = safe_into_ptr(msgs);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_sync_state(umsgs: *mut *const UnwrappedMessages, user: *mut Author) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            let mut msgs = Vec::new();
            loop {
                let m = user.fetch_next_msgs();
                if m.is_empty() {
                    break;
                }
                msgs.extend(m);
            }
            *umsgs = safe_into_ptr(msgs);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_state(state: *mut *const UserState, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        state.as_mut().map_or(Err::NullArgument, |state| {
            user.fetch_state().map_or_else(operation_failed, |st| {
                *state = safe_into_ptr(st);
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_store_psk(c_pskid: *mut *const PskId, c_user: *mut Author, c_psk_seed: *const c_char) -> Err {
    if c_psk_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_psk_seed).to_str().map_or(Err::BadArgument, |psk_seed| {
        c_user.as_mut().map_or(Err::NullArgument, |user| {
            c_pskid.as_mut().map_or(Err::NullArgument, |pskid| {
                let psk = psk_from_seed(psk_seed.as_ref());
                let id = pskid_from_psk(&psk);
                user.store_psk(id, psk).map_or_else(operation_failed, |_| {
                    *pskid = safe_into_ptr(id);
                    Err::Ok
                })
            })
        })
    })
}

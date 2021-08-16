use super::*;

pub type Subscriber = iota_streams::app_channels::api::tangle::Subscriber<TransportWrap>;

/// Create a new subscriber
#[no_mangle]
pub unsafe extern "C" fn sub_new(
    c_sub: *mut *mut Subscriber,
    c_seed: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_sub.as_mut().map_or(Err::NullArgument, |sub| {
                let user = Subscriber::new(seed, tsp.clone());
                *sub = safe_into_mut_ptr(user);
                Err::Ok
            })
        })
    })
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub unsafe extern "C" fn sub_recover(
    c_sub: *mut *mut Subscriber,
    c_seed: *const c_char,
    c_ann_address: *const Address,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        c_ann_address.as_ref().map_or(Err::NullArgument, |addr| {
            transport.as_ref().map_or(Err::NullArgument, |tsp| {
                c_sub.as_mut().map_or(Err::NullArgument, |sub| {
                    Subscriber::recover(seed, addr, tsp.clone()).map_or(Err::OperationFailed, |user| {
                        *sub = safe_into_mut_ptr(user);
                        Err::Ok
                    })
                })
            })
        })
    })
}

/// Import an Author instance from an encrypted binary array
#[no_mangle]
pub unsafe extern "C" fn sub_import(
    c_sub: *mut *mut Subscriber,
    buffer: Buffer,
    c_password: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_sub.as_mut().map_or(Err::NullArgument, |sub| {
                let bytes_vec: Vec<_> = buffer.into();
                Subscriber::import(&bytes_vec, password, tsp.clone()).map_or(Err::OperationFailed, |user| {
                    *sub = safe_into_mut_ptr(user);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_export(buf: *mut Buffer, c_sub: *mut Subscriber, c_password: *const c_char) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        c_sub.as_ref().map_or(Err::NullArgument, |user| {
            buf.as_mut().map_or(Err::NullArgument, |buf| {
                user.export(password).map_or(Err::OperationFailed, |bytes| {
                    *buf = bytes.into();
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub extern "C" fn sub_drop(user: *mut Subscriber) {
    safe_drop_mut_ptr(user)
}

/// Channel app instance.
#[no_mangle]
pub unsafe extern "C" fn sub_channel_address(addr: *mut *const ChannelAddress, user: *const Subscriber) -> Err {
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
pub unsafe extern "C" fn sub_is_multi_branching(flag: *mut uint8_t, user: *const Subscriber) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        flag.as_mut().map_or(Err::NullArgument, |flag| {
            *flag = if user.is_multi_branching() { 1 } else { 0 };
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_get_public_key(pk: *mut *const PublicKey, user: *const Subscriber) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        pk.as_mut().map_or(Err::NullArgument, |pk| {
            *pk = user.get_public_key() as *const PublicKey;
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_author_public_key(pk: *mut *const PublicKey, user: *const Subscriber) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        pk.as_mut().map_or(Err::NullArgument, |pk| {
            user.author_public_key().map_or(Err::OperationFailed, |public_key| {
                *pk = public_key as *const PublicKey;
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_is_registered(user: *const Subscriber) -> u8 {
    user.as_ref().map_or(0, |user| if user.is_registered() { 1 } else { 0 })
}

#[no_mangle]
pub unsafe extern "C" fn sub_unregister(user: *mut Subscriber) {
    user.as_mut().map_or((), |user| {
        user.unregister();
    })
}

/// Handle Channel app instance announcement.
#[no_mangle]
pub unsafe extern "C" fn sub_receive_announce(user: *mut Subscriber, link: *const Address) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            user.receive_announcement(link)
                .map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

/// Subscribe to a Channel app instance.
#[no_mangle]
pub unsafe extern "C" fn sub_send_subscribe(
    r: *mut *const Address,
    user: *mut Subscriber,
    announcement_link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            announcement_link
                .as_ref()
                .map_or(Err::NullArgument, |announcement_link| -> Err {
                    user.send_subscribe(announcement_link)
                        .map_or(Err::OperationFailed, |link| -> Err {
                            *r = safe_into_ptr(link);
                            Err::Ok
                        })
                })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut Subscriber,
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
                        .map_or(Err::OperationFailed, |response| {
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

#[no_mangle]
pub unsafe extern "C" fn sub_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut Subscriber,
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
                        .map_or(Err::OperationFailed, |response| {
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

/// Process a keyload message
#[no_mangle]
pub unsafe extern "C" fn sub_receive_keyload(user: *mut Subscriber, link: *const Address) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            user.receive_keyload(link).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_receive_sequence(
    r: *mut *const Address,
    user: *mut Subscriber,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_sequence(link).map_or(Err::OperationFailed, |seq_link| {
                    *r = safe_into_ptr(seq_link);
                    Err::Ok
                })
            })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn sub_receive_tagged_packet(
    r: *mut PacketPayloads,
    user: *mut Subscriber,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_tagged_packet(link)
                    .map_or(Err::OperationFailed, |tagged_payloads| {
                        *r = tagged_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn sub_receive_signed_packet(
    r: *mut PacketPayloads,
    user: *mut Subscriber,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_signed_packet(link)
                    .map_or(Err::OperationFailed, |signed_payloads| {
                        *r = signed_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_gen_next_msg_ids(ids: *mut *const NextMsgIds, user: *mut Subscriber) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        ids.as_mut().map_or(Err::NullArgument, |ids| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            *ids = safe_into_ptr(next_msg_ids);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_receive_keyload_from_ids(
    r: *mut MessageLinks,
    user: *mut Subscriber,
    next_msg_ids: *const NextMsgIds,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            next_msg_ids.as_ref().map_or(Err::NullArgument, |ids| {
                for (_pk, cursor) in ids {
                    if let Ok(keyload_link) = user.receive_sequence(&cursor.link) {
                        match user.receive_keyload(&keyload_link) {
                            Ok(true) => {
                                *r = (cursor.link.clone(), Some(keyload_link)).into();
                                return Err::Ok;
                            }
                            Ok(false) => {}
                            Err(_) => return Err::OperationFailed,
                        }
                    }
                }
                Err::OperationFailed
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_receive_msg(
    r: *mut *const UnwrappedMessage,
    user: *mut Subscriber,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_msg(link).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_receive_msg_by_sequence(
    r: *mut *const UnwrappedMessage,
    user: *mut Subscriber,
    anchor_link: *const Address,
    msg_num: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            anchor_link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_msg_by_sequence(link, msg_num as u32).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}


#[no_mangle]
pub unsafe extern "C" fn sub_fetch_next_msgs(r: *mut *const UnwrappedMessages, user: *mut Subscriber) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            let m = user.fetch_next_msgs();
            *r = safe_into_ptr(m);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_fetch_prev_msg(m: *mut *const UnwrappedMessage, user: *mut Subscriber, address: *const Address) -> Err {
    m.as_mut().map_or(Err::NullArgument, |m| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                user.fetch_prev_msg(addr).map_or(Err::OperationFailed, |msg| {
                    *m = safe_into_ptr(msg);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_fetch_prev_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut Subscriber, address: *const Address, num_msgs: size_t) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                user.fetch_prev_msgs(addr, num_msgs).map_or(Err::OperationFailed, |msgs| {
                    *umsgs = safe_into_ptr(msgs);
                    Err::Ok
                })
            })
        })
    })
}


#[no_mangle]
pub unsafe extern "C" fn sub_sync_state(r: *mut *const UnwrappedMessages, user: *mut Subscriber) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            let mut ms = Vec::new();
            loop {
                let m = user.fetch_next_msgs();
                if m.is_empty() {
                    break;
                }
                ms.extend(m);
            }
            *r = safe_into_ptr(ms);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_fetch_state(state: *mut *const UserState, user: *mut Subscriber) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        state.as_mut().map_or(Err::NullArgument, |state| {
            user.fetch_state().map_or(Err::OperationFailed, |st| {
                *state = safe_into_ptr(st);
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_reset_state(user: *mut Subscriber) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        user.reset_state().map_or(Err::OperationFailed, |_| Err::Ok)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sub_store_psk(c_pskid: *mut *const PskId, c_user: *mut Subscriber, c_psk_seed: *const c_char) -> Err {
    if c_psk_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_psk_seed).to_str().map_or(Err::BadArgument, |psk_seed| {
        c_user.as_mut().map_or(Err::NullArgument, |user| {
            c_pskid.as_mut().map_or(Err::NullArgument, |pskid| {
                let psk = psk_from_seed(psk_seed.as_ref());
                let id = pskid_from_psk(&psk);
                user.store_psk(id, psk).map_or(Err::OperationFailed, |_| {
                    *pskid = safe_into_ptr(id);
                    Err::Ok
                })
            })
        })
    })
}

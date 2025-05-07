// SPDX-License-Identifier: MIT

#[macro_export]
macro_rules! try_nl80211 {
    ($msg: expr) => {{
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use $crate::Nl80211Error;

        match $msg {
            Ok(msg) => {
                let (header, payload) = msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(msg) => msg,
                    NetlinkPayload::Error(err) => {
                        return Err(Nl80211Error::NetlinkError(err))
                    }
                    _ => {
                        return Err(Nl80211Error::UnexpectedMessage(
                            NetlinkMessage::new(header, payload),
                        ))
                    }
                }
            }
            Err(e) => {
                return Err(Nl80211Error::Bug(format!(
                    "BUG: decode error {:?}",
                    e
                )))
            }
        }
    }};
}

#[cfg(test)]
pub(crate) mod test {
    #[macro_export]
    macro_rules! roundtrip_emit_parse_test {
        ($name:ident, $ty:ty, $new:expr$(,)?) => {
            #[test]
            fn $name() {
                let val: $ty = $new;

                // to check if the type can be emitted to a buffer greater than
                // the needed size
                let mut buffer = vec![0; val.buffer_len() + 1];
                val.emit(buffer.as_mut_slice());

                assert_eq!(
                    <$ty>::parse(&buffer[0..val.buffer_len()]).unwrap(),
                    val,
                );
            }
        };
    }

    macro_rules! roundtrip_from_test {
        ($name:ident, $from:ty => $into:ty, $new:expr$(,)?) => {
            #[test]
            fn $name() {
                let val: $from = $new;

                let into: $into = val.into();

                assert_eq!(<$from>::from(into), val,);
            }
        };
    }

    pub(crate) use roundtrip_emit_parse_test;
    pub(crate) use roundtrip_from_test;
}

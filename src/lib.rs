use nom::{
    bits::{bits, complete::take},
    combinator::map_res,
    sequence::tuple,
    IResult,
};

/// The MQTT Control packet types
/// ref: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_2.1_-
#[derive(Debug, PartialEq, Clone)]
enum PacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    PingReq,
    PingResp,
    Disconnect,
}

struct InvalidPacketTypeError(u8);

impl TryFrom<u8> for PacketType {
    type Error = InvalidPacketTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::Connect),
            2 => Ok(PacketType::Connack),
            3 => Ok(PacketType::Publish),
            4 => Ok(PacketType::Puback),
            5 => Ok(PacketType::PubRec),
            6 => Ok(PacketType::PubRel),
            7 => Ok(PacketType::PubComp),
            8 => Ok(PacketType::Subscribe),
            9 => Ok(PacketType::Suback),
            10 => Ok(PacketType::Unsubscribe),
            11 => Ok(PacketType::Unsuback),
            12 => Ok(PacketType::PingReq),
            13 => Ok(PacketType::PingResp),
            14 => Ok(PacketType::Disconnect),
            _ => Err(InvalidPacketTypeError(value)),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
struct FixedHeader {
    /// MQTT Control Packet type
    packet_type: PacketType,
    /// Flags specific to each MQTT Control Packet type
    packet_flags: u8,
    /// the number of bytes remaining within the current packet,
    /// including data in the variable header and the payload.
    remaining_length: i32,
}

impl FixedHeader {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        for a in input {
            println!("Parsing 0b{:08b}", a);
        }
        let (input, (packet_type, packet_flags)) = packet_byte(input)?;
        let (input, remaining_length) = remaining_length(input)?;
        Ok((
            input,
            Self {
                packet_type,
                packet_flags,
                remaining_length,
            },
        ))
    }
}

/// Parse first byte of MQTT Fixed header returning the packet type and flags specific to each MQTT Control Packet Type
fn packet_byte(input: &[u8]) -> IResult<&[u8], (PacketType, u8)> {
    let packet_parser = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
        take(4_usize),
        take(4_usize),
    )));
    map_res::<_, _, _, _, InvalidPacketTypeError, _, _>(
        packet_parser,
        |(packet_type, packet_flags): (u8, u8)| Ok((packet_type.try_into()?, packet_flags)),
    )(input)
}

/// Remaining length can be up to four bytes depending on most significant bit being 1
fn remaining_length(input: &[u8]) -> IResult<&[u8], i32> {
    let mut accumulator = 0_i32;
    let mut index = 0_u32;
    let mut input = input;
    loop {
        let _input = input.clone();
        // Read off the most significant bit as continuation indicator and remaining 7 bits as the value
        let (i, (continuation, length_value)): (_, (u8, u8)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take(1_usize),
                take(7_usize),
            )))(_input)?;

        input = i;

        // Add as if sequential bytes
        accumulator = accumulator + ((length_value as i32) << index);

        // Break if most significant bit isn't 1 and hence all remaining bits being 1 i.e. 0xFF
        // indicating there's more bytes in the remaining length value
        if continuation != 1 {
            break;
        }

        index += 7;
    }

    Ok((input, accumulator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_fixed_header_one_remaining_length() {
        assert_eq!(
            FixedHeader::parse(b"\x20\x7f"),
            nom::IResult::Ok((
                &b""[..],
                FixedHeader {
                    packet_type: PacketType::Connack,
                    packet_flags: 0,
                    remaining_length: 127,
                },
            ))
        );
    }

    #[test]
    fn test_decode_fixed_header_multiple_remaining_length1() {
        assert_eq!(
            FixedHeader::parse(b"\x10\xc1\x02"),
            nom::IResult::Ok((
                &b""[..],
                FixedHeader {
                    packet_type: PacketType::Connect,
                    packet_flags: 0x00,
                    remaining_length: 321,
                },
            ))
        );
    }

    #[test]
    fn test_decode_fixed_header_multiple_remaining_length() {
        assert_eq!(
            FixedHeader::parse(b"\x3C\x82\x7f"),
            nom::IResult::Ok((
                &b""[..],
                FixedHeader {
                    packet_type: PacketType::Publish,
                    packet_flags: 0x0C,
                    remaining_length: 16258,
                },
            ))
        );
    }
}

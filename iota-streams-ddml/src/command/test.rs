use core::str::FromStr;
use iota_streams_core::{
    key_exchange::x25519,
    prelude::{
        string::{
            String,
            ToString,
        },
        typenum::{
            U32,
            U64,
        },
        Vec,
    },
    prng,
    signature::ed25519,
    sponge::{
        prp::{
            keccak::KeccakF1600,
            PRP,
        },
        spongos::Spongos,
    },
    try_or,
    Errors::*,
    Result,
};

use crate::{
    command::*,
    io,
    link_store::SingleLinkStore,
    types::*,
};

fn should_fail(r: iota_streams_core::Result<()>) -> iota_streams_core::Result<()> {
    match r {
        Ok(()) => iota_streams_core::err(iota_streams_core::Errors::TestShouldFail),
        Err(_) => Ok(()),
    }
}

fn absorb_mask_u8<F: PRP>() -> Result<()> {
    let mut buf = vec![0_u8; 2];
    let mut tag_wrap = External(NBytes::<U32>::default());
    let mut tag_unwrap = External(NBytes::<U32>::default());
    let key = Key::from_bytes([0; 32]);

    for t in 0_u8..10_u8 {
        let t = Uint8(t);
        let buf_size = sizeof::Context::<F>::new()
            .absorb_key(External(&key))?
            .absorb(t)?
            .mask(t)?
            .get_size();
        let buf_size2 = sizeof::Context::<F>::new().absorb(&t)?.mask(&t)?.get_size();
        try_or!(buf_size == buf_size2, ValueMismatch(buf_size, buf_size2))?;
        try_or!(buf_size == 2, ValueMismatch(2, buf_size))?;

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.absorb_key(External(&key))?
                .commit()?
                .absorb(&t)?
                .mask(&t)?
                .commit()?
                .squeeze(&mut tag_wrap)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut t2 = Uint8(0_u8);
        let mut t3 = Uint8(0_u8);
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.absorb_key(External(&key))?
                .commit()?
                .absorb(&mut t2)?
                .mask(&mut t3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        try_or!(t == t2, ValueMismatch(t.0 as usize, t2.0 as usize))?;
        try_or!(t == t3, ValueMismatch(t.0 as usize, t3.0 as usize))?;
        try_or!(
            tag_wrap == tag_unwrap,
            InvalidTagSqueeze(tag_wrap.0.to_string(), tag_unwrap.0.to_string())
        )?;
    }
    Ok(())
}

#[test]
fn test_u8() -> Result<()> {
    absorb_mask_u8::<KeccakF1600>()
}

fn absorb_mask_size<F: PRP>() -> Result<()> {
    let mut tag_wrap = External(NBytes::<U32>::default());
    let mut tag_unwrap = External(NBytes::<U32>::default());
    let key = Key::from_bytes([0; 32]);

    let ns = [0, 1, 13, 14, 25, 26, 27, 39, 40, 81, 9840, 9841, 9842, 19683];

    for n in ns.iter() {
        let s = Size(*n);
        let buf_size = sizeof::Context::<F>::new().absorb(s)?.mask(s)?.get_size();
        let buf_size2 = sizeof::Context::<F>::new().absorb(&s)?.mask(&s)?.get_size();
        try_or!(buf_size == buf_size2, ValueMismatch(buf_size, buf_size2))?;

        let mut buf = vec![0_u8; buf_size];

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.absorb_key(External(&key))?
                .commit()?
                .absorb(&s)?
                .mask(&s)?
                .commit()?
                .squeeze(&mut tag_wrap)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut s2 = Size::default();
        let mut s3 = Size::default();
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.absorb_key(External(&key))?
                .commit()?
                .absorb(&mut s2)?
                .mask(&mut s3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        try_or!(s == s2, ValueMismatch(s.0, s2.0))?;
        try_or!(s == s3, ValueMismatch(s.0, s3.0))?;
        try_or!(
            tag_wrap == tag_unwrap,
            InvalidTagSqueeze(tag_wrap.0.to_string(), tag_unwrap.0.to_string())
        )?;
    }
    Ok(())
}

#[test]
fn size() -> Result<()> {
    absorb_mask_size::<KeccakF1600>()
}

fn absorb_mask_squeeze_bytes_mac<F: PRP>() -> Result<()> {
    const NS: [usize; 10] = [0, 3, 255, 256, 257, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = External(NBytes::<U32>::default());
    let mut tag_unwrap = External(NBytes::<U32>::default());
    let key = External(Key::from_bytes([0; 32]));

    let prng = prng::dbg_init_str::<F>("TESTPRNGKEY");
    let nonce = "TESTPRNGNONCE".as_bytes().to_vec();

    for n in NS.iter() {
        let ta = Bytes(prng.gen_n(&nonce, *n));
        // nonce.slice_mut().inc();
        let nta = NBytes::<U64>(prng.gen_arr(&nonce));
        // nonce.slice_mut().inc();
        let enta = NBytes::<U64>(prng.gen_arr(&nonce));
        // nonce.slice_mut().inc();
        let tm = Bytes(prng.gen_n(&nonce, *n));
        // nonce.slice_mut().inc();
        let ntm = NBytes::<U64>(prng.gen_arr(&nonce));
        // nonce.slice_mut().inc();
        let mut ents = External(NBytes::<U64>::default());
        // nonce.slice_mut().inc();
        let mac = Mac(*n);

        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.commit()?
                .absorb_key(&key)?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&ents)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&tag_wrap)?;
            ctx.get_size()
        };
        let mut buf = vec![0_u8; buf_size];

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.commit()?
                .absorb_key(&key)?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&mut ents)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&mut tag_wrap)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut ta2 = Bytes::default();
        let mut nta2 = NBytes::<U64>::default();
        let mut tm2 = Bytes::default();
        let mut ntm2 = NBytes::<U64>::default();
        let mut ents2 = External(NBytes::<U64>::default());
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.commit()?
                .absorb_key(&key)?
                .absorb(&mut ta2)?
                .absorb(&mut nta2)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&mut tm2)?
                .mask(&mut ntm2)?
                .commit()?
                .squeeze(&mut ents2)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        try_or!(ta == ta2, InvalidBytes(ta.to_string(), ta2.to_string()))?;
        try_or!(nta == nta2, InvalidBytes(nta.to_string(), nta2.to_string()))?;
        // try_or!(tm == tm2, "Invalid unwrapped tm value: {:?} != {:?}", tm, tm2);
        // try_or!(ntm == ntm2, "Invalid unwrapped ntm value: {:?} != {:?}", ntm, ntm2);
        // try_or!(ents == ents2, "Invalid unwrapped ents value: {:?} != {:?}", ents, ents2);
        try_or!(
            tag_wrap == tag_unwrap,
            InvalidTagSqueeze(tag_wrap.0.to_string(), tag_unwrap.0.to_string())
        )?;
    }

    Ok(())
}

#[test]
fn bytes() -> Result<()> {
    absorb_mask_squeeze_bytes_mac::<KeccakF1600>()
}

fn absorb_ed25519<F: PRP>() -> Result<()> {
    let secret = ed25519::SecretKey::from_bytes([7; ed25519::SECRET_KEY_LENGTH]);
    let public = secret.public_key();

    let ta = Bytes([3_u8; 17].to_vec());
    let mut uta = Bytes(Vec::new());
    let mut hash = External(NBytes::<U64>::default());
    let mut uhash = External(NBytes::<U64>::default());

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.absorb(&ta)?
            .commit()?
            .squeeze(&hash)?
            .ed25519(&secret, &hash)?
            .ed25519(&secret, HashSig)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.absorb(&ta)?
            .commit()?
            .squeeze(&mut hash)?
            .ed25519(&secret, &hash)?
            .ed25519(&secret, HashSig)?;
        try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.absorb(&mut uta)?
            .commit()?
            .squeeze(&mut uhash)?
            .ed25519(&public, &uhash)?
            .ed25519(&public, HashSig)?;
        try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    try_or!(ta == uta, InvalidTagSqueeze(ta.to_string(), uta.to_string()))?;
    try_or!(
        hash == uhash,
        InvalidHashSqueeze(hash.0.to_string(), uhash.0.to_string())
    )?;
    Ok(())
}

#[test]
fn test_ed25519() -> Result<()> {
    absorb_ed25519::<KeccakF1600>()
}

fn x25519_static<F: PRP>() -> Result<()> {
    let secret_a = x25519::SecretKey::from_bytes([11; 32]);
    let secret_b = x25519::SecretKey::from_bytes([13; 32]);
    let public_a = secret_a.public_key();
    let public_b = secret_b.public_key();
    let mut public_b2 = x25519::PublicKey::from([0_u8; 32]);

    let ta = Bytes([3_u8; 17].to_vec());
    let mut uta = Bytes(Vec::new());

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.absorb(&public_b)?
            .x25519(&secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.absorb(&public_b)?
            .x25519(&secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.absorb(&mut public_b2)?
            .x25519(&secret_a, &public_b2)?
            .commit()?
            .mask(&mut uta)?;
        try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    try_or!(ta == uta, InvalidTagSqueeze(ta.to_string(), uta.to_string()))?;

    Ok(())
}

fn x25519_transport<F: PRP>() -> Result<()> {
    let secret_a = x25519::SecretKey::generate().unwrap();
    let public_a = secret_a.public_key();

    let key = NBytes::<U32>::default();
    let mut ukey = NBytes::<U32>::default();

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.x25519(&public_a, &key)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.x25519(&public_a, &key)?;
        try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.x25519(&secret_a, &mut ukey)?;
        try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
    }

    try_or!(key == ukey, InvalidKeySqueeze(key.to_string(), ukey.to_string()))?;

    Ok(())
}

#[test]
fn test_x25519_static() -> Result<()> {
    x25519_static::<KeccakF1600>()
    // x25519_ephemeral::<KeccakF1600>()
}

#[test]
fn test_x25519_transport() -> Result<()> {
    x25519_transport::<KeccakF1600>()
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct Link;

impl ToString for Link {
    fn to_string(&self) -> String {
        "Link".to_string()
    }
}

impl<F> SkipFallback<F> for Link {
    fn sizeof_skip(&self, _ctx: &mut sizeof::Context<F>) -> Result<()> {
        Ok(())
    }
    fn wrap_skip<OS: io::OStream>(&self, _ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream>(&mut self, _ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        Ok(())
    }
}

fn tagged_packet<F: PRP>() -> Result<()> {
    let link = Link;
    let inner = {
        let mut s = Spongos::<F>::init();
        s.absorb_key([0; 32]);
        s.commit();
        s.to_inner()
    };
    let store = SingleLinkStore::<F, Link, ()>::new(link, (inner, ()));

    {
        let public_payload = Bytes::from_str("public_payload").unwrap();
        let masked_payload = Bytes::from_str("masked_payload").unwrap();
        let mac = Mac(16);

        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.join(&store, &link)?
                .commit()?
                .absorb(&public_payload)?
                .mask(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            ctx.get_size()
        };
        let mut buf = vec![0_u8; buf_size];

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.join(&store, &link)?
                .commit()?
                .absorb(&public_payload)?
                .mask(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut link2 = Link;
        let mut public_payload2 = Bytes::default();
        let mut masked_payload2 = Bytes::default();
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.join(&store, &mut link2)?
                .commit()?
                .absorb(&mut public_payload2)?
                .mask(&mut masked_payload2)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        try_or!(
            public_payload == public_payload2,
            InvalidBytes(public_payload.to_string(), public_payload2.to_string())
        )?;
        try_or!(
            masked_payload == masked_payload2,
            InvalidBytes(masked_payload.to_string(), masked_payload2.to_string())
        )?;
    }

    Ok(())
}

fn tagged_packet2<F: PRP>() -> Result<()> {
    let link = Link;
    let (inner0, inner1) = {
        let mut s = Spongos::<F>::init();
        let inner0 = s.get_inner();
        s.absorb(&[0]);
        s.commit();
        let inner1 = s.to_inner();
        (inner0, inner1)
    };
    // inner0 is all-zeros
    let store0 = SingleLinkStore::<F, Link, ()>::new(link, (inner0, ()));
    // inner1 is pseudo-random
    let store1 = SingleLinkStore::<F, Link, ()>::new(link, (inner1, ()));

    {
        let public_payload = Bytes::from_str("PPP").unwrap();
        let masked_payload = Bytes::from_str("MMM").unwrap();
        let mac = Mac(16);

        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.join(&store0, &link)?
                .absorb(&public_payload)?
                .mask(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            ctx.get_size()
        };

        let mut buf0 = vec![0_u8; buf_size];
        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf0[..]);
            ctx.join(&store0, &link)?
                .absorb(&public_payload)?
                .mask(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut buf1 = vec![0_u8; buf_size];
        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf1[..]);
            ctx.join(&store0, &link)?
                .absorb(&public_payload)?
                .absorb(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        // When inner state is all-zero mask in the first block
        // will be indistinguishable from absorb.
        // This can only happen either with negligible probability
        // or by logic mistake.
        assert_eq!(buf0, buf1);

        let mut buf2 = vec![0_u8; buf_size];
        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf2[..]);
            ctx.join(&store1, &link)?
                .absorb(&public_payload)?
                .mask(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        let mut buf3 = vec![0_u8; buf_size];
        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf3[..]);
            ctx.join(&store1, &link)?
                .absorb(&public_payload)?
                .absorb(&masked_payload)?
                .commit()?
                .squeeze(&mac)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        // This is the correct case where the joined inner state
        // is not all-zero.
        assert!(buf2 != buf3);
    }

    Ok(())
}

#[test]
fn test_tagged_packet() -> Result<()> {
    tagged_packet::<KeccakF1600>()
}

#[test]
fn test_tagged_packet2() -> Result<()> {
    should_fail(tagged_packet2::<KeccakF1600>())
}

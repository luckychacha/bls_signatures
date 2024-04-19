use blst::min_sig::{PublicKey, SecretKey, Signature};
use rand::Rng;
use std::str;
fn main() {
    // 初始化随机数生成器
    let mut rng = rand::thread_rng();
    let sk_bytes: [u8; 32] = rng.gen();
    println!("Random secret key: {:?}", sk_bytes);

    // 生成密钥
    let sk = SecretKey::key_gen(&sk_bytes, &[]).unwrap();
    println!("Secret key: {:?}", sk);
    println!("Secret key to bytes: {:?}", sk.to_bytes());
    println!("Secret key to hex: {}", hex::encode(sk.to_bytes()));

    // 创建签名
    let msg = b"Hello, world!";
    let fake_msg = b"Hello, world";
    let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"; // DST字符串
    // dst into &[u8]
    let dst = dst.as_bytes();
    let sig = sk.sign(msg, dst, &[]);
    println!("Signature: {:?}", sig);
    println!("Signature to bytes: {:?}", sig.to_bytes());
    println!("Signature compress: {:?}", sig.compress());

    let a = sig.compress();
    let b = Signature::uncompress(&a);
    println!("uncompress: {:?}", b);
    println!("hex: {}", hex::encode(sig.to_bytes()));

    // 生成公钥
    let pk = sk.sk_to_pk();
    println!("Public key: {:?}", pk);

    // 验证签名
    let sig_groupcheck = true;
    let pk_validate = true;
    let res: blst::BLST_ERROR = sig.verify(sig_groupcheck, msg, dst, &[], &pk, pk_validate);
    println!("Signature verification result: {:?}", res);


    let res = sig.verify(sig_groupcheck, fake_msg, dst, &[], &pk, pk_validate);
    println!("Signature verification result: {:?}", res);
}

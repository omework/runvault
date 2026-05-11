use age::secrecy::{ExposeSecret, SecretString};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    symm::Cipher,
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{crypto::maybe_decrypt_file_payload, error::Error, profile::Profile};

const ROOT_KEY_BITS: u32 = 4096;
const LEAF_KEY_BITS: u32 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiInitOptions {
    pub common_name: Option<String>,
    pub days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiIssueOptions {
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addrs: Vec<IpAddr>,
    pub client: bool,
    pub server: bool,
    pub days: u32,
}

pub fn init_profile_pki(
    profile_path: &Path,
    password: SecretString,
    options: &PkiInitOptions,
) -> Result<PathBuf, Error> {
    let profile = Profile::from_path(profile_path)?;
    let profile_dir = profile_dir(profile_path)?;
    let root_dir = profile_dir.join("pki").join("ca").join("root");
    let root_key_path = root_dir.join("root.key.pem");
    let root_cert_path = root_dir.join("root.crt.pem");
    let root_chain_path = root_dir.join("root.chain.pem");

    for path in [&root_key_path, &root_cert_path, &root_chain_path] {
        if path.exists() {
            return Err(Error::AlreadyExists(path.clone()));
        }
    }

    std::fs::create_dir_all(&root_dir).map_err(|source| Error::WriteFile {
        path: root_dir.clone(),
        source,
    })?;

    let common_name = options
        .common_name
        .clone()
        .unwrap_or_else(|| format!("{} Root CA", profile.name));
    if common_name.trim().is_empty() {
        return Err(Error::Pki(
            "root CA common name must not be empty".to_string(),
        ));
    }

    let key = generate_rsa_key(ROOT_KEY_BITS)?;
    let cert = build_root_certificate(&key, &common_name, options.days)?;
    write_encrypted_pem(
        &root_key_path,
        &key.private_key_to_pem_pkcs8().map_err(pki_error)?,
        password,
    )?;
    let cert_pem = cert.to_pem().map_err(pki_error)?;
    write_pem(&root_cert_path, &cert_pem)?;
    write_pem(&root_chain_path, &cert_pem)?;
    Ok(root_dir)
}

pub fn issue_profile_certificate(
    profile_path: &Path,
    password: SecretString,
    name: &str,
    options: &PkiIssueOptions,
) -> Result<PathBuf, Error> {
    validate_leaf_name(name)?;
    let profile_dir = profile_dir(profile_path)?;
    let root_dir = profile_dir.join("pki").join("ca").join("root");
    let root_key_path = root_dir.join("root.key.pem");
    let root_cert_path = root_dir.join("root.crt.pem");

    let root_key = load_private_key_with_password(&root_key_path, password.clone())?;
    let root_cert = load_certificate(&root_cert_path)?;

    let issued_dir = profile_dir.join("pki").join("issued").join(name);
    let leaf_key_path = issued_dir.join(format!("{name}.key.pem"));
    let leaf_cert_path = issued_dir.join(format!("{name}.crt.pem"));
    let leaf_chain_path = issued_dir.join(format!("{name}.chain.pem"));

    for path in [&leaf_key_path, &leaf_cert_path, &leaf_chain_path] {
        if path.exists() {
            return Err(Error::AlreadyExists(path.clone()));
        }
    }

    std::fs::create_dir_all(&issued_dir).map_err(|source| Error::WriteFile {
        path: issued_dir.clone(),
        source,
    })?;

    let mut dns_names = options.dns_names.clone();
    let mut client = options.client;
    let mut server = options.server;
    if !client && !server {
        client = true;
        server = true;
    }
    if server && dns_names.is_empty() && options.ip_addrs.is_empty() {
        dns_names.push(name.to_string());
    }

    let common_name = options
        .common_name
        .clone()
        .unwrap_or_else(|| name.to_string());
    if common_name.trim().is_empty() {
        return Err(Error::Pki(
            "issued certificate common name must not be empty".to_string(),
        ));
    }

    let key = generate_rsa_key(LEAF_KEY_BITS)?;
    let cert = build_leaf_certificate(
        &key,
        &root_key,
        &root_cert,
        name,
        &common_name,
        &dns_names,
        &options.ip_addrs,
        client,
        server,
        options.days,
    )?;

    write_encrypted_pem(
        &leaf_key_path,
        &key.private_key_to_pem_pkcs8().map_err(pki_error)?,
        password,
    )?;
    write_pem(&leaf_cert_path, &cert.to_pem().map_err(pki_error)?)?;
    write_pem(&leaf_chain_path, &root_cert.to_pem().map_err(pki_error)?)?;
    Ok(issued_dir)
}

fn build_root_certificate(
    key: &PKey<Private>,
    common_name: &str,
    days: u32,
) -> Result<X509, Error> {
    let mut builder = X509Builder::new().map_err(pki_error)?;
    builder.set_version(2).map_err(pki_error)?;
    let serial = random_serial()?;
    builder.set_serial_number(&serial).map_err(pki_error)?;

    let name = x509_name(common_name)?;
    builder.set_subject_name(&name).map_err(pki_error)?;
    builder.set_issuer_name(&name).map_err(pki_error)?;
    builder.set_pubkey(key).map_err(pki_error)?;
    builder
        .set_not_before(Asn1Time::days_from_now(0).map_err(pki_error)?.as_ref())
        .map_err(pki_error)?;
    builder
        .set_not_after(Asn1Time::days_from_now(days).map_err(pki_error)?.as_ref())
        .map_err(pki_error)?;

    let basic = BasicConstraints::new()
        .critical()
        .ca()
        .pathlen(0)
        .build()
        .map_err(pki_error)?;
    builder.append_extension(basic).map_err(pki_error)?;
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(pki_error)?;
    builder.append_extension(key_usage).map_err(pki_error)?;
    let ski = {
        let context = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(pki_error)?
    };
    builder.append_extension(ski).map_err(pki_error)?;
    let aki = {
        let context = builder.x509v3_context(None, None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&context)
            .map_err(pki_error)?
    };
    builder.append_extension(aki).map_err(pki_error)?;
    builder
        .sign(key, MessageDigest::sha256())
        .map_err(pki_error)?;
    Ok(builder.build())
}

#[allow(clippy::too_many_arguments)]
fn build_leaf_certificate(
    key: &PKey<Private>,
    issuer_key: &PKey<Private>,
    issuer_cert: &X509,
    leaf_name: &str,
    common_name: &str,
    dns_names: &[String],
    ip_addrs: &[IpAddr],
    client: bool,
    server: bool,
    days: u32,
) -> Result<X509, Error> {
    let mut builder = X509Builder::new().map_err(pki_error)?;
    builder.set_version(2).map_err(pki_error)?;
    let serial = random_serial()?;
    builder.set_serial_number(&serial).map_err(pki_error)?;
    let subject = x509_name(common_name)?;
    builder.set_subject_name(&subject).map_err(pki_error)?;
    builder
        .set_issuer_name(issuer_cert.subject_name())
        .map_err(pki_error)?;
    builder.set_pubkey(key).map_err(pki_error)?;
    builder
        .set_not_before(Asn1Time::days_from_now(0).map_err(pki_error)?.as_ref())
        .map_err(pki_error)?;
    builder
        .set_not_after(Asn1Time::days_from_now(days).map_err(pki_error)?.as_ref())
        .map_err(pki_error)?;

    let basic = BasicConstraints::new()
        .critical()
        .build()
        .map_err(pki_error)?;
    builder.append_extension(basic).map_err(pki_error)?;
    let mut key_usage = KeyUsage::new();
    key_usage.critical().digital_signature();
    if server {
        key_usage.key_encipherment();
    }
    builder
        .append_extension(key_usage.build().map_err(pki_error)?)
        .map_err(pki_error)?;

    let mut eku = ExtendedKeyUsage::new();
    if client {
        eku.client_auth();
    }
    if server {
        eku.server_auth();
    }
    builder
        .append_extension(eku.build().map_err(pki_error)?)
        .map_err(pki_error)?;

    if !dns_names.is_empty() || !ip_addrs.is_empty() {
        let san = {
            let context = builder.x509v3_context(Some(issuer_cert), None);
            let mut san = SubjectAlternativeName::new();
            for dns_name in dns_names {
                san.dns(dns_name);
            }
            for ip_addr in ip_addrs {
                san.ip(&ip_addr.to_string());
            }
            san.build(&context).map_err(pki_error)?
        };
        builder.append_extension(san).map_err(pki_error)?;
    } else if server {
        let san = {
            let context = builder.x509v3_context(Some(issuer_cert), None);
            SubjectAlternativeName::new()
                .dns(leaf_name)
                .build(&context)
                .map_err(pki_error)?
        };
        builder.append_extension(san).map_err(pki_error)?;
    }

    let ski = {
        let context = builder.x509v3_context(Some(issuer_cert), None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(pki_error)?
    };
    builder.append_extension(ski).map_err(pki_error)?;
    let aki = {
        let context = builder.x509v3_context(Some(issuer_cert), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&context)
            .map_err(pki_error)?
    };
    builder.append_extension(aki).map_err(pki_error)?;
    builder
        .sign(issuer_key, MessageDigest::sha256())
        .map_err(pki_error)?;
    Ok(builder.build())
}

fn generate_rsa_key(bits: u32) -> Result<PKey<Private>, Error> {
    let rsa = Rsa::generate(bits).map_err(pki_error)?;
    PKey::from_rsa(rsa).map_err(pki_error)
}

fn load_private_key_with_password(
    path: &Path,
    password: SecretString,
) -> Result<PKey<Private>, Error> {
    let bytes = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let pem = maybe_decrypt_file_payload(&bytes, password)?;
    PKey::private_key_from_pem(&pem).map_err(pki_error)
}

fn load_certificate(path: &Path) -> Result<X509, Error> {
    let pem = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    X509::from_pem(&pem).map_err(pki_error)
}

fn write_pem(path: &Path, contents: &[u8]) -> Result<(), Error> {
    std::fs::write(path, contents).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn write_encrypted_pem(path: &Path, contents: &[u8], password: SecretString) -> Result<(), Error> {
    let key = PKey::private_key_from_pem(contents).map_err(pki_error)?;
    let encrypted = key
        .private_key_to_pem_pkcs8_passphrase(
            Cipher::aes_256_cbc(),
            password.expose_secret().as_bytes(),
        )
        .map_err(pki_error)?;
    std::fs::write(path, encrypted).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn profile_dir(profile_path: &Path) -> Result<PathBuf, Error> {
    profile_path.parent().map(Path::to_path_buf).ok_or_else(|| {
        Error::InvalidProfile(format!(
            "profile path '{}' does not have a parent directory",
            profile_path.display()
        ))
    })
}

fn x509_name(common_name: &str) -> Result<openssl::x509::X509Name, Error> {
    let mut builder = X509NameBuilder::new().map_err(pki_error)?;
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(pki_error)?;
    Ok(builder.build())
}

fn random_serial() -> Result<Asn1Integer, Error> {
    let mut serial = BigNum::new().map_err(pki_error)?;
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .map_err(pki_error)?;
    serial.to_asn1_integer().map_err(pki_error)
}

fn validate_leaf_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() {
        return Err(Error::Pki(
            "issued certificate name must not be empty".to_string(),
        ));
    }
    let path = Path::new(name);
    if path.components().count() != 1 || path.file_name().is_none() {
        return Err(Error::Pki(format!(
            "issued certificate name '{}' must be a single path segment",
            name
        )));
    }
    Ok(())
}

fn pki_error(err: openssl::error::ErrorStack) -> Error {
    Error::Pki(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::{PkiInitOptions, PkiIssueOptions, init_profile_pki, issue_profile_certificate};
    use crate::profile::{CreateProfileOptions, create_profile, resolve_profile_path};
    use age::secrecy::SecretString;
    use std::{net::IpAddr, path::PathBuf, str::FromStr};
    use tempfile::tempdir;

    #[test]
    fn initializes_profile_root_ca() {
        let dir = tempdir().unwrap();
        let profile_dir = dir.path().join("service");
        create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("service".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();
        let profile_path = resolve_profile_path(&profile_dir);

        let root_dir = init_profile_pki(
            &profile_path,
            SecretString::from("secret".to_string()),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
            },
        )
        .unwrap();

        let root_key = std::fs::read_to_string(root_dir.join("root.key.pem")).unwrap();
        assert!(root_key.contains("BEGIN ENCRYPTED PRIVATE KEY"));
        assert!(root_dir.join("root.crt.pem").exists());
        assert!(root_dir.join("root.chain.pem").exists());
    }

    #[test]
    fn issues_leaf_certificate_signed_by_profile_root() {
        let dir = tempdir().unwrap();
        let profile_dir = dir.path().join("service");
        create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("service".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();
        let profile_path = resolve_profile_path(&profile_dir);

        init_profile_pki(
            &profile_path,
            SecretString::from("secret".to_string()),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
            },
        )
        .unwrap();

        let issued_dir = issue_profile_certificate(
            &profile_path,
            SecretString::from("secret".to_string()),
            "api.service.local",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec![],
                ip_addrs: vec![IpAddr::from_str("127.0.0.1").unwrap()],
                client: false,
                server: true,
                days: 825,
            },
        )
        .unwrap();

        let root = openssl::x509::X509::from_pem(
            &std::fs::read(
                profile_dir
                    .join("pki")
                    .join("ca")
                    .join("root")
                    .join("root.crt.pem"),
            )
            .unwrap(),
        )
        .unwrap();
        let leaf = openssl::x509::X509::from_pem(
            &std::fs::read(issued_dir.join("api.service.local.crt.pem")).unwrap(),
        )
        .unwrap();
        assert!(leaf.verify(root.public_key().unwrap().as_ref()).unwrap());
        assert!(issued_dir.join("api.service.local.key.pem").exists());
        assert!(issued_dir.join("api.service.local.chain.pem").exists());
    }
}

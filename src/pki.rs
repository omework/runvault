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
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{crypto::maybe_decrypt_file_payload, error::Error};

const ROOT_KEY_BITS: u32 = 4096;
const LEAF_KEY_BITS: u32 = 2048;
const PKI_SCHEMA_VERSION: u8 = 1;
const PKI_DIR_NAME: &str = "pki";
const PKI_INFRA_FILE_NAME: &str = "infra.yaml";
pub const DEFAULT_ROOT_CA_DAYS: u32 = 3650;
const PKI_URI_SCHEME: &str = "pki://";
const PKI_CA_NAME: &str = "ca";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PkiMaterialFile {
    Key,
    Cert,
    Chain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiInitOptions {
    pub common_name: Option<String>,
    pub days: u32,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiIssueOptions {
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addrs: Vec<IpAddr>,
    pub client: bool,
    pub server: bool,
    pub days: u32,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiInfraDocument {
    #[serde(default = "default_pki_schema_version")]
    pub schema_version: u8,
    pub root: PkiRootRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issued: Vec<PkiIssuedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiRootRecord {
    pub common_name: String,
    pub days: u32,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub chain_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiIssuedRecord {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_addrs: Vec<IpAddr>,
    pub client: bool,
    pub server: bool,
    pub days: u32,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub chain_path: PathBuf,
}

pub fn pki_root_dir() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".runvault").join(PKI_DIR_NAME))
        .ok_or_else(|| Error::Pki("HOME is not set; cannot resolve ~/.runvault/pki".to_string()))
}

pub fn pki_infra_path() -> Result<PathBuf, Error> {
    Ok(pki_root_dir()?.join(PKI_INFRA_FILE_NAME))
}

pub fn resolve_pki_uri(path: &Path) -> Result<Option<PathBuf>, Error> {
    let Some(raw) = path.to_str() else {
        return Ok(None);
    };
    let Some(raw_path) = raw.strip_prefix(PKI_URI_SCHEME) else {
        return Ok(None);
    };
    let segments = raw_path.split('/').collect::<Vec<_>>();
    let [name, file_name] = segments.as_slice() else {
        return Err(Error::Pki(format!(
            "invalid PKI URI '{}'; expected pki://<name>/<key.pem|crt.pem|chain.pem>",
            raw
        )));
    };
    if name.trim().is_empty() {
        return Err(Error::Pki(format!(
            "invalid PKI URI '{}'; certificate name must not be empty",
            raw
        )));
    }
    let file = parse_pki_material_file(file_name, raw)?;
    let root = pki_root_dir()?;
    let resolved = if *name == PKI_CA_NAME {
        root.join(PKI_CA_NAME).join(file.file_name())
    } else {
        validate_leaf_name(name)?;
        root.join("issued").join(name).join(file.file_name())
    };
    Ok(Some(resolved))
}

pub fn init_infra_pki(password: SecretString, options: &PkiInitOptions) -> Result<PathBuf, Error> {
    let root_dir = pki_root_dir()?;
    init_infra_pki_at(&root_dir, password, options)
}

pub fn issue_infra_certificate(
    password: SecretString,
    name: &str,
    options: &PkiIssueOptions,
) -> Result<PathBuf, Error> {
    let root_dir = pki_root_dir()?;
    issue_infra_certificate_at(&root_dir, password, name, options)
}

pub fn rotate_infra_certificates(password: SecretString) -> Result<(), Error> {
    let root_dir = pki_root_dir()?;
    rotate_infra_certificates_at(&root_dir, password)
}

fn default_init_options() -> PkiInitOptions {
    PkiInitOptions {
        common_name: None,
        days: DEFAULT_ROOT_CA_DAYS,
        force: false,
    }
}

fn ensure_infra_pki_at(root_dir: &Path, password: SecretString) -> Result<(), Error> {
    let infra_path = root_dir.join(PKI_INFRA_FILE_NAME);
    if infra_path.exists() {
        return Ok(());
    }

    init_infra_pki_at(root_dir, password, &default_init_options())?;
    Ok(())
}

fn init_infra_pki_at(
    root_dir: &Path,
    password: SecretString,
    options: &PkiInitOptions,
) -> Result<PathBuf, Error> {
    let pki_dir = root_dir.to_path_buf();
    let infra_path = pki_dir.join(PKI_INFRA_FILE_NAME);
    let root_key_rel = PathBuf::from("ca").join("key.pem");
    let root_cert_rel = PathBuf::from("ca").join("crt.pem");
    let root_chain_rel = PathBuf::from("ca").join("chain.pem");
    let root_key_path = pki_dir.join(&root_key_rel);
    let root_cert_path = pki_dir.join(&root_cert_rel);
    let root_chain_path = pki_dir.join(&root_chain_rel);

    for path in [
        &infra_path,
        &root_key_path,
        &root_cert_path,
        &root_chain_path,
    ] {
        if path.exists() && !options.force {
            return Err(Error::AlreadyExists(path.clone()));
        }
    }

    let existing_issued = if options.force && infra_path.exists() {
        match load_infra_document(&infra_path) {
            Ok(infra) => infra.issued,
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let root_material_dir = root_key_path
        .parent()
        .ok_or_else(|| Error::Pki("root key path has no parent directory".to_string()))?;
    std::fs::create_dir_all(root_material_dir).map_err(|source| Error::WriteFile {
        path: root_material_dir.to_path_buf(),
        source,
    })?;

    let common_name = options
        .common_name
        .clone()
        .unwrap_or_else(|| "Runvault Root CA".to_string());
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
        password.clone(),
    )?;
    let cert_pem = cert.to_pem().map_err(pki_error)?;
    write_pem(&root_cert_path, &cert_pem)?;
    write_pem(&root_chain_path, &cert_pem)?;

    save_infra_document(
        &infra_path,
        &PkiInfraDocument {
            schema_version: default_pki_schema_version(),
            root: PkiRootRecord {
                common_name,
                days: options.days,
                key_path: root_key_rel,
                cert_path: root_cert_rel,
                chain_path: root_chain_rel,
            },
            issued: existing_issued.clone(),
        },
    )?;

    for issued in &existing_issued {
        let key_path = pki_dir.join(&issued.key_path);
        let cert_path = pki_dir.join(&issued.cert_path);
        let chain_path = pki_dir.join(&issued.chain_path);
        let common_name = issued
            .common_name
            .clone()
            .unwrap_or_else(|| issued.name.clone());
        write_leaf_materials(
            &key_path,
            &cert_path,
            &chain_path,
            &key,
            &cert,
            &common_name,
            &issued.name,
            &issued.dns_names,
            &issued.ip_addrs,
            issued.client,
            issued.server,
            issued.days,
            password.clone(),
        )?;
    }

    Ok(root_material_dir.to_path_buf())
}

fn issue_infra_certificate_at(
    root_dir: &Path,
    password: SecretString,
    name: &str,
    options: &PkiIssueOptions,
) -> Result<PathBuf, Error> {
    validate_leaf_name(name)?;
    ensure_infra_pki_at(root_dir, password.clone())?;
    let pki_dir = root_dir.to_path_buf();
    let infra_path = pki_dir.join(PKI_INFRA_FILE_NAME);
    let mut infra = load_infra_document(&infra_path)?;

    let existing_issued_index = infra.issued.iter().position(|issued| issued.name == name);
    if existing_issued_index.is_some() && !options.force {
        return Err(Error::AlreadyExists(pki_dir.join("issued").join(name)));
    }

    let root_key =
        load_private_key_with_password(&pki_dir.join(&infra.root.key_path), password.clone())?;
    let root_cert = load_certificate(&pki_dir.join(&infra.root.cert_path))?;

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

    let common_name = options.common_name.clone();
    let resolved_common_name = common_name.clone().unwrap_or_else(|| name.to_string());
    if resolved_common_name.trim().is_empty() {
        return Err(Error::Pki(
            "issued certificate common name must not be empty".to_string(),
        ));
    }

    let key_rel = PathBuf::from("issued").join(name).join("key.pem");
    let cert_rel = PathBuf::from("issued").join(name).join("crt.pem");
    let chain_rel = PathBuf::from("issued").join(name).join("chain.pem");
    let key_path = pki_dir.join(&key_rel);
    let cert_path = pki_dir.join(&cert_rel);
    let chain_path = pki_dir.join(&chain_rel);

    for path in [&key_path, &cert_path, &chain_path] {
        if path.exists() && !options.force {
            return Err(Error::AlreadyExists(path.clone()));
        }
    }

    write_leaf_materials(
        &key_path,
        &cert_path,
        &chain_path,
        &root_key,
        &root_cert,
        &resolved_common_name,
        name,
        &dns_names,
        &options.ip_addrs,
        client,
        server,
        options.days,
        password,
    )?;

    let issued_record = PkiIssuedRecord {
        name: name.to_string(),
        common_name,
        dns_names,
        ip_addrs: options.ip_addrs.clone(),
        client,
        server,
        days: options.days,
        key_path: key_rel,
        cert_path: cert_rel,
        chain_path: chain_rel,
    };
    if let Some(index) = existing_issued_index {
        infra.issued[index] = issued_record;
    } else {
        infra.issued.push(issued_record);
    }
    save_infra_document(&infra_path, &infra)?;

    Ok(cert_path
        .parent()
        .ok_or_else(|| Error::Pki("issued certificate path has no parent directory".to_string()))?
        .to_path_buf())
}

fn rotate_infra_certificates_at(root_dir: &Path, password: SecretString) -> Result<(), Error> {
    ensure_infra_pki_at(root_dir, password.clone())?;
    let pki_dir = root_dir.to_path_buf();
    let infra_path = pki_dir.join(PKI_INFRA_FILE_NAME);
    let infra = load_infra_document(&infra_path)?;

    let root_key =
        load_private_key_with_password(&pki_dir.join(&infra.root.key_path), password.clone())?;
    let root_cert = load_certificate(&pki_dir.join(&infra.root.cert_path))?;

    for issued in &infra.issued {
        let key_path = pki_dir.join(&issued.key_path);
        let cert_path = pki_dir.join(&issued.cert_path);
        let chain_path = pki_dir.join(&issued.chain_path);
        let common_name = issued
            .common_name
            .clone()
            .unwrap_or_else(|| issued.name.clone());
        write_leaf_materials(
            &key_path,
            &cert_path,
            &chain_path,
            &root_key,
            &root_cert,
            &common_name,
            &issued.name,
            &issued.dns_names,
            &issued.ip_addrs,
            issued.client,
            issued.server,
            issued.days,
            password.clone(),
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_leaf_materials(
    key_path: &Path,
    cert_path: &Path,
    chain_path: &Path,
    root_key: &PKey<Private>,
    root_cert: &X509,
    common_name: &str,
    leaf_name: &str,
    dns_names: &[String],
    ip_addrs: &[IpAddr],
    client: bool,
    server: bool,
    days: u32,
    password: SecretString,
) -> Result<(), Error> {
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let key = generate_rsa_key(LEAF_KEY_BITS)?;
    let cert = build_leaf_certificate(
        &key,
        root_key,
        root_cert,
        leaf_name,
        common_name,
        dns_names,
        ip_addrs,
        client,
        server,
        days,
    )?;

    write_encrypted_pem(
        key_path,
        &key.private_key_to_pem_pkcs8().map_err(pki_error)?,
        password,
    )?;
    write_pem(cert_path, &cert.to_pem().map_err(pki_error)?)?;
    write_pem(chain_path, &root_cert.to_pem().map_err(pki_error)?)?;
    Ok(())
}

fn load_infra_document(path: &Path) -> Result<PkiInfraDocument, Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let infra: PkiInfraDocument = serde_yaml::from_str(&content)
        .map_err(|source| Error::Pki(format!("failed to parse {}: {}", path.display(), source)))?;
    if infra.schema_version != PKI_SCHEMA_VERSION {
        return Err(Error::Pki(format!(
            "unsupported PKI infra schema version {}",
            infra.schema_version
        )));
    }
    Ok(infra)
}

fn save_infra_document(path: &Path, infra: &PkiInfraDocument) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let yaml = serde_yaml::to_string(infra)
        .map_err(|source| Error::Pki(format!("failed to serialize PKI infra: {}", source)))?;
    std::fs::write(path, yaml).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn default_pki_schema_version() -> u8 {
    PKI_SCHEMA_VERSION
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
    if name == PKI_CA_NAME {
        return Err(Error::Pki(
            "issued certificate name 'ca' is reserved".to_string(),
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

impl PkiMaterialFile {
    fn file_name(self) -> &'static str {
        match self {
            Self::Key => "key.pem",
            Self::Cert => "crt.pem",
            Self::Chain => "chain.pem",
        }
    }
}

fn parse_pki_material_file(value: &str, raw_uri: &str) -> Result<PkiMaterialFile, Error> {
    match value {
        "key.pem" => Ok(PkiMaterialFile::Key),
        "crt.pem" => Ok(PkiMaterialFile::Cert),
        "chain.pem" => Ok(PkiMaterialFile::Chain),
        _ => Err(Error::Pki(format!(
            "invalid PKI URI '{}'; filename must be one of key.pem, crt.pem, or chain.pem",
            raw_uri
        ))),
    }
}

fn pki_error(err: openssl::error::ErrorStack) -> Error {
    Error::Pki(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_ROOT_CA_DAYS, PkiInitOptions, PkiIssueOptions, init_infra_pki_at,
        issue_infra_certificate_at, load_infra_document, resolve_pki_uri,
        rotate_infra_certificates_at, validate_leaf_name,
    };
    use crate::error::Error;
    use age::secrecy::SecretString;
    use std::{net::IpAddr, path::Path, str::FromStr};
    use tempfile::tempdir;

    #[test]
    fn initializes_machine_level_root_ca_and_infra_inventory() {
        let dir = tempdir().unwrap();

        let root_dir = init_infra_pki_at(
            dir.path(),
            SecretString::from("secret".to_string()),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
                force: false,
            },
        )
        .unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        assert_eq!(infra.root.common_name, "Runvault Root CA");
        let root_key = std::fs::read_to_string(root_dir.join("key.pem")).unwrap();
        assert!(root_key.contains("BEGIN ENCRYPTED PRIVATE KEY"));
        assert!(root_dir.join("crt.pem").exists());
        assert!(root_dir.join("chain.pem").exists());
    }

    #[test]
    fn issues_leaf_certificate_and_tracks_it_in_infra_yaml() {
        let dir = tempdir().unwrap();
        init_infra_pki_at(
            dir.path(),
            SecretString::from("secret".to_string()),
            &PkiInitOptions {
                common_name: Some("Infra Root".to_string()),
                days: 3650,
                force: false,
            },
        )
        .unwrap();

        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            SecretString::from("secret".to_string()),
            "api.service.local",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec!["api.service.local".to_string()],
                ip_addrs: vec![IpAddr::from_str("127.0.0.1").unwrap()],
                client: false,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        assert_eq!(infra.issued.len(), 1);
        assert_eq!(infra.issued[0].name, "api.service.local");
        assert!(issued_dir.join("key.pem").exists());
        assert!(issued_dir.join("crt.pem").exists());
        assert!(issued_dir.join("chain.pem").exists());
    }

    #[test]
    fn rotates_leaf_materials_from_tracked_inventory() {
        let dir = tempdir().unwrap();
        let password = SecretString::from("secret".to_string());
        init_infra_pki_at(
            dir.path(),
            password.clone(),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
                force: false,
            },
        )
        .unwrap();
        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            password.clone(),
            "service",
            &PkiIssueOptions {
                common_name: Some("service".to_string()),
                dns_names: vec!["service.example.com".to_string()],
                ip_addrs: vec![],
                client: true,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();
        let key_before = std::fs::read(issued_dir.join("key.pem")).unwrap();

        rotate_infra_certificates_at(dir.path(), password).unwrap();

        let key_after = std::fs::read(issued_dir.join("key.pem")).unwrap();
        assert_ne!(key_before, key_after);
    }

    #[test]
    fn rejects_duplicate_issued_name() {
        let dir = tempdir().unwrap();
        let password = SecretString::from("secret".to_string());
        init_infra_pki_at(
            dir.path(),
            password.clone(),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
                force: false,
            },
        )
        .unwrap();
        issue_infra_certificate_at(
            dir.path(),
            password.clone(),
            "shared-name",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec![],
                ip_addrs: vec![],
                client: true,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();

        let err = issue_infra_certificate_at(
            dir.path(),
            password,
            "shared-name",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec![],
                ip_addrs: vec![],
                client: true,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::AlreadyExists(_)));
    }

    #[test]
    fn issue_auto_initializes_missing_infra() {
        let dir = tempdir().unwrap();

        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            SecretString::from("secret".to_string()),
            "api.service.local",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec![],
                ip_addrs: vec![],
                client: false,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        assert_eq!(infra.root.common_name, "Runvault Root CA");
        assert_eq!(infra.root.days, DEFAULT_ROOT_CA_DAYS);
        assert_eq!(infra.issued.len(), 1);
        assert!(issued_dir.join("crt.pem").exists());
    }

    #[test]
    fn rotate_auto_initializes_missing_infra() {
        let dir = tempdir().unwrap();

        rotate_infra_certificates_at(dir.path(), SecretString::from("secret".to_string())).unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        assert_eq!(infra.root.common_name, "Runvault Root CA");
        assert_eq!(infra.root.days, DEFAULT_ROOT_CA_DAYS);
        assert!(infra.issued.is_empty());
    }

    #[test]
    fn force_init_overwrites_root_and_reissues_tracked_leafs() {
        let dir = tempdir().unwrap();
        let password = SecretString::from("secret".to_string());

        init_infra_pki_at(
            dir.path(),
            password.clone(),
            &PkiInitOptions {
                common_name: Some("Initial Root".to_string()),
                days: 3650,
                force: false,
            },
        )
        .unwrap();
        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            password.clone(),
            "service",
            &PkiIssueOptions {
                common_name: Some("service".to_string()),
                dns_names: vec!["service.example.com".to_string()],
                ip_addrs: vec![],
                client: true,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();
        let root_before = std::fs::read(dir.path().join("ca/crt.pem")).unwrap();
        let leaf_before = std::fs::read(issued_dir.join("crt.pem")).unwrap();

        init_infra_pki_at(
            dir.path(),
            password,
            &PkiInitOptions {
                common_name: Some("Replacement Root".to_string()),
                days: 3650,
                force: true,
            },
        )
        .unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        let root_after = std::fs::read(dir.path().join("ca/crt.pem")).unwrap();
        let leaf_after = std::fs::read(issued_dir.join("crt.pem")).unwrap();

        assert_eq!(infra.root.common_name, "Replacement Root");
        assert_eq!(infra.issued.len(), 1);
        assert_ne!(root_before, root_after);
        assert_ne!(leaf_before, leaf_after);
    }

    #[test]
    fn force_issue_overwrites_existing_leaf_material() {
        let dir = tempdir().unwrap();
        let password = SecretString::from("secret".to_string());

        init_infra_pki_at(
            dir.path(),
            password.clone(),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
                force: false,
            },
        )
        .unwrap();
        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            password.clone(),
            "shared-name",
            &PkiIssueOptions {
                common_name: Some("initial".to_string()),
                dns_names: vec!["initial.example.com".to_string()],
                ip_addrs: vec![],
                client: false,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();
        let leaf_before = std::fs::read(issued_dir.join("crt.pem")).unwrap();

        issue_infra_certificate_at(
            dir.path(),
            password,
            "shared-name",
            &PkiIssueOptions {
                common_name: Some("replacement".to_string()),
                dns_names: vec!["replacement.example.com".to_string()],
                ip_addrs: vec![],
                client: true,
                server: true,
                days: 900,
                force: true,
            },
        )
        .unwrap();

        let infra = load_infra_document(&dir.path().join("infra.yaml")).unwrap();
        let leaf_after = std::fs::read(issued_dir.join("crt.pem")).unwrap();

        assert_eq!(infra.issued.len(), 1);
        assert_eq!(infra.issued[0].common_name.as_deref(), Some("replacement"));
        assert_eq!(infra.issued[0].dns_names, vec!["replacement.example.com"]);
        assert!(infra.issued[0].client);
        assert!(infra.issued[0].server);
        assert_eq!(infra.issued[0].days, 900);
        assert_ne!(leaf_before, leaf_after);
    }

    #[test]
    fn supports_wildcard_dns_names() {
        let dir = tempdir().unwrap();
        let password = SecretString::from("secret".to_string());
        init_infra_pki_at(
            dir.path(),
            password.clone(),
            &PkiInitOptions {
                common_name: None,
                days: 3650,
                force: false,
            },
        )
        .unwrap();

        let issued_dir = issue_infra_certificate_at(
            dir.path(),
            password,
            "caddy-workers",
            &PkiIssueOptions {
                common_name: None,
                dns_names: vec!["*.workers.api.mata35.fsb.home".to_string()],
                ip_addrs: vec![],
                client: false,
                server: true,
                days: 825,
                force: false,
            },
        )
        .unwrap();

        let leaf =
            openssl::x509::X509::from_pem(&std::fs::read(issued_dir.join("crt.pem")).unwrap())
                .unwrap();
        let san = leaf.subject_alt_names().unwrap();
        assert!(
            san.iter()
                .any(|name| { name.dnsname() == Some("*.workers.api.mata35.fsb.home") })
        );
    }

    #[test]
    fn resolves_pki_uris_for_ca_and_issued_material() {
        let home = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
        }

        let ca = resolve_pki_uri(Path::new("pki://ca/crt.pem"))
            .unwrap()
            .expect("expected pki uri resolution");
        let issued = resolve_pki_uri(Path::new("pki://api.service.local/key.pem"))
            .unwrap()
            .expect("expected pki uri resolution");

        assert_eq!(ca, home.path().join(".runvault/pki/ca/crt.pem"));
        assert_eq!(
            issued,
            home.path()
                .join(".runvault/pki/issued/api.service.local/key.pem")
        );

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn rejects_reserved_ca_as_issued_name() {
        let err = validate_leaf_name("ca").unwrap_err();
        assert!(matches!(err, Error::Pki(_)));
    }
}

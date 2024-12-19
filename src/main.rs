use std::convert::TryFrom;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

extern crate clap;
use clap::{Parser, Subcommand};
extern crate flate2;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

extern crate sha1;
use sha1::{Digest, Sha1};

#[derive(Parser)]
#[command(name = "git")]
#[command(about = "A git implementation", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "init")]
    Init {},
    #[command(name = "hash-object")]
    HashObject {
        #[arg(short = 'w')]
        write: bool,
        #[arg(required = true)]
        path: PathBuf,
    },
    #[command(name = "ls-tree")]
    LsTree {
        #[arg(long = "name-only")]
        name_only: bool,
        #[arg(required = true)]
        hash: String,
    },
    #[command(name = "cat-file")]
    CatFile {
        #[arg(short = 'p')]
        pretty: bool,
        #[arg(required = true)]
        hash: String,
    },
    #[command(name = "write-tree")]
    WriteTree {},
    #[command(name = "commit-tree")]
    CommitTree {
        #[arg(required = true)]
        tree: String,
        #[arg(short = 'p')]
        parent: Option<String>,
        #[arg(short = 'm')]
        message: String,
    },
}

#[derive(Debug)]
enum GitError {
    InvalidObjectType(String),
    InvalidObjectFormat(String),
    InvalidTreeEntry(String),
    InvalidHash(String),
    ObjectNotFound(String),
    IoError(io::Error),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GitError::InvalidObjectType(msg) => write!(f, "Invalid object type: {}", msg),
            GitError::InvalidObjectFormat(msg) => write!(f, "Invalid object format: {}", msg),
            GitError::InvalidTreeEntry(msg) => write!(f, "Invalid tree entry: {}", msg),
            GitError::InvalidHash(msg) => write!(f, "Invalid hash: {}", msg),
            GitError::ObjectNotFound(msg) => write!(f, "Object not found: {}", msg),
            GitError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for GitError {}

impl From<io::Error> for GitError {
    fn from(err: io::Error) -> GitError {
        GitError::IoError(err)
    }
}

#[derive(Debug, PartialEq)]
enum GitObjectType {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl TryFrom<&str> for GitObjectType {
    type Error = GitError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "blob" => Ok(GitObjectType::Blob),
            "tree" => Ok(GitObjectType::Tree),
            "commit" => Ok(GitObjectType::Commit),
            "tag" => Ok(GitObjectType::Tag),
            _ => Err(GitError::InvalidObjectType(format!(
                "Unknown object type: {}",
                s
            ))),
        }
    }
}

#[derive(Debug)]
struct GitObject {
    object_type: GitObjectType,
    size: usize,
    content: Vec<u8>,
}

#[derive(Debug)]
struct TreeEntry {
    mode: String,
    name: String,
    sha: [u8; 20],
}

impl TreeEntry {
    fn new(mode: String, name: String, sha: [u8; 20]) -> Self {
        Self { mode, name, sha }
    }

    fn format_sha(&self) -> String {
        self.sha.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn is_tree(&self) -> bool {
        self.mode.starts_with("40000")
    }

    fn format_output(&self, name_only: bool) -> String {
        if name_only {
            self.name.clone()
        } else {
            let formatted_mode = if self.is_tree() {
                format!("0{}", self.mode)
            } else {
                self.mode.clone()
            };

            format!(
                "{} {} {}    {}",
                formatted_mode,
                if self.is_tree() { "tree" } else { "blob" },
                self.format_sha(),
                self.name
            )
        }
    }
}

struct GitRepo {
    root_path: PathBuf,
}

impl GitRepo {
    fn new() -> Self {
        Self {
            root_path: PathBuf::from(".git"),
        }
    }

    fn create_dir_if_not_exists(&self, path: &Path) -> Result<(), GitError> {
        match fs::create_dir(path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if path.is_dir() {
                    Ok(())
                } else {
                    Err(GitError::IoError(e))
                }
            }
            Err(e) => Err(GitError::IoError(e)),
        }
    }

    fn write_file_if_different(&self, path: &Path, contents: &[u8]) -> Result<(), GitError> {
        match fs::read(path) {
            Ok(existing_contents) if existing_contents == contents => Ok(()),
            Ok(_) => {
                fs::write(path, contents)?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::write(path, contents)?;
                Ok(())
            }
            Err(e) => Err(GitError::IoError(e)),
        }
    }

    fn init(&self) -> Result<(), GitError> {
        self.create_dir_if_not_exists(&self.root_path)?;
        self.create_dir_if_not_exists(&self.root_path.join("objects"))?;
        self.create_dir_if_not_exists(&self.root_path.join("refs"))?;

        self.write_file_if_different(&self.root_path.join("HEAD"), b"ref: refs/heads/main\n")?;

        println!("Initialized git directory");
        Ok(())
    }

    fn read_object(&self, hash: &str) -> Result<GitObject, GitError> {
        if hash.len() < 3 {
            return Err(GitError::InvalidHash("Hash too short".to_string()));
        }

        let (dir, file) = hash.split_at(2);
        let path = self.root_path.join("objects").join(dir).join(file);

        let compressed_data = fs::read(&path)
            .map_err(|_| GitError::ObjectNotFound(format!("Object {} not found", hash)))?;

        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)?;

        self.parse_object(decompressed_data)
    }

    fn parse_object(&self, data: Vec<u8>) -> Result<GitObject, GitError> {
        let header_end = data
            .iter()
            .position(|&x| x == 0)
            .ok_or_else(|| GitError::InvalidObjectFormat("No null byte found".to_string()))?;

        let header = String::from_utf8_lossy(&data[..header_end]);
        let parts: Vec<&str> = header.split(' ').collect();

        if parts.len() != 2 {
            return Err(GitError::InvalidObjectFormat(
                "Invalid header format".to_string(),
            ));
        }

        let object_type = GitObjectType::try_from(parts[0])?;
        let size = parts[1]
            .parse::<usize>()
            .map_err(|_| GitError::InvalidObjectFormat("Invalid size in header".to_string()))?;

        Ok(GitObject {
            object_type,
            size,
            content: data[header_end + 1..].to_vec(),
        })
    }

    fn parse_tree_entries(&self, content: &[u8]) -> Result<Vec<TreeEntry>, GitError> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos < content.len() {
            let null_pos = content[pos..]
                .iter()
                .position(|&x| x == 0)
                .ok_or_else(|| GitError::InvalidTreeEntry("No null byte found".to_string()))?;

            let entry_data = String::from_utf8_lossy(&content[pos..pos + null_pos]);
            let parts: Vec<&str> = entry_data.split(' ').collect();

            if parts.len() != 2 {
                return Err(GitError::InvalidTreeEntry(
                    "Invalid entry format".to_string(),
                ));
            }

            let mode = parts[0].to_string();
            let name = parts[1].to_string();

            let sha_start = pos + null_pos + 1;
            if sha_start + 20 > content.len() {
                return Err(GitError::InvalidTreeEntry("Invalid SHA length".to_string()));
            }

            let mut sha = [0u8; 20];
            sha.copy_from_slice(&content[sha_start..sha_start + 20]);

            entries.push(TreeEntry::new(mode, name, sha));
            pos = sha_start + 20;
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn hash_object(&self, path: &Path, write: bool) -> Result<String, GitError> {
        let data = fs::read(path)?;
        let content = String::from_utf8_lossy(&data);
        let blob_string = format!("blob {}\0{}", content.len(), content);

        let mut hasher = Sha1::new();
        hasher.update(&blob_string);
        let result = hasher.finalize();
        let sha_hash = format!("{:x}", result);

        if write {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(blob_string.as_bytes())?;
            let compressed_bytes = encoder.finish()?;

            let dir = &sha_hash[..2];
            let filename = &sha_hash[2..];
            let object_dir = self.root_path.join("objects").join(dir);
            let object_path = object_dir.join(filename);

            self.create_dir_if_not_exists(&object_dir)?;
            self.write_file_if_different(&object_path, &compressed_bytes)?;
        }

        Ok(sha_hash)
    }

    fn ls_tree(&self, hash: &str, name_only: bool) -> Result<(), GitError> {
        let object = self.read_object(hash)?;

        if object.object_type != GitObjectType::Tree {
            return Err(GitError::InvalidObjectType("Not a tree object".to_string()));
        }

        let entries = self.parse_tree_entries(&object.content)?;

        for entry in entries {
            println!("{}", entry.format_output(name_only));
        }

        Ok(())
    }

    fn write_tree(&self) -> Result<String, GitError> {
        self.write_tree_recursive(&PathBuf::from("."))
    }

    fn write_tree_recursive(&self, dir: &Path) -> Result<String, GitError> {
        let mut entries = Vec::new();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = path
                .file_name()
                .ok_or_else(|| {
                    GitError::IoError(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid file name",
                    ))
                })?
                .to_string_lossy()
                .into_owned();

            if name == ".git" || name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata()?;
            let (mode, hash) = if metadata.is_dir() {
                ("40000", self.write_tree_recursive(&path)?)
            } else {
                ("100644", self.hash_object(&path, true)?)
            };

            let mut sha = [0u8; 20];
            for i in 0..20 {
                sha[i] = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
                    .map_err(|_| GitError::InvalidHash("Invalid hash format".to_string()))?;
            }

            entries.push(TreeEntry::new(mode.to_string(), name, sha));
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let mut content = Vec::new();
        for entry in entries {
            content.extend_from_slice(format!("{} {}\0", entry.mode, entry.name).as_bytes());
            content.extend_from_slice(&entry.sha);
        }

        let header = format!("tree {}\0", content.len());
        let mut full_content = Vec::new();
        full_content.extend_from_slice(header.as_bytes());
        full_content.extend_from_slice(&content);

        let mut hasher = Sha1::new();
        hasher.update(&full_content);
        let result = hasher.finalize();
        let sha_hash = format!("{:x}", result);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&full_content)?;
        let compressed_bytes = encoder.finish()?;

        let dir_name = &sha_hash[..2];
        let file_name = &sha_hash[2..];
        let object_dir = self.root_path.join("objects").join(dir_name);
        let object_path = object_dir.join(file_name);

        self.create_dir_if_not_exists(&object_dir)?;
        self.write_file_if_different(&object_path, &compressed_bytes)?;

        Ok(sha_hash)
    }

    fn cat_file(&self, hash: &str) -> Result<(), GitError> {
        let object = self.read_object(hash)?;

        if object.object_type != GitObjectType::Blob {
            return Err(GitError::InvalidObjectType("Not a blob object".to_string()));
        }

        print!("{}", String::from_utf8_lossy(&object.content));
        Ok(())
    }

    fn create_commit(
        &self,
        tree: &str,
        parent: Option<&str>,
        message: &str,
    ) -> Result<String, GitError> {
        let author = "Shubham Hazra <shubhamhazra1234@gmail.com>";
        let committer = author;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timezone = "+0000";

        let mut content = Vec::new();

        content.extend_from_slice(format!("tree {}\n", tree).as_bytes());

        if let Some(parent_hash) = parent {
            content.extend_from_slice(format!("parent {}\n", parent_hash).as_bytes());
        }

        content.extend_from_slice(
            format!(
                "author {} {} {}\n\
                 committer {} {} {}\n\
                 \n\
                 {}\n",
                author, timestamp, timezone, committer, timestamp, timezone, message
            )
            .as_bytes(),
        );

        let header = format!("commit {}\0", content.len());
        let mut full_content = Vec::new();
        full_content.extend_from_slice(header.as_bytes());
        full_content.extend_from_slice(&content);

        let mut hasher = Sha1::new();
        hasher.update(&full_content);
        let result = hasher.finalize();
        let sha_hash = format!("{:x}", result);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&full_content)?;
        let compressed_bytes = encoder.finish()?;

        let dir_name = &sha_hash[..2];
        let file_name = &sha_hash[2..];
        let object_dir = self.root_path.join("objects").join(dir_name);
        let object_path = object_dir.join(file_name);

        self.create_dir_if_not_exists(&object_dir)?;
        self.write_file_if_different(&object_path, &compressed_bytes)?;

        Ok(sha_hash)
    }
}

fn main() -> Result<(), GitError> {
    let cli = Cli::parse();
    let repo = GitRepo::new();

    match cli.command {
        Commands::Init {} => repo.init(),
        Commands::HashObject { write, path } => {
            let hash = repo.hash_object(&path, write)?;
            println!("{}", hash);
            Ok(())
        }
        Commands::LsTree { name_only, hash } => repo.ls_tree(&hash, name_only),
        Commands::CatFile { pretty: _, hash } => repo.cat_file(&hash),
        Commands::WriteTree {} => {
            let hash = repo.write_tree()?;
            println!("{}", hash);
            Ok(())
        }
        Commands::CommitTree {
            tree,
            parent,
            message,
        } => {
            let hash = repo.create_commit(&tree, parent.as_deref(), &message)?;
            println!("{}", hash);
            Ok(())
        }
    }
}

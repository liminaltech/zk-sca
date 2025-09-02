use alloc::{format, string::ToString, vec::Vec};
use core::{
    hash::{Hash, Hasher},
    ops::Deref,
};
use nonempty::NonEmpty;
use spdx::{Expression as SpdxExpr, LicenseReq};

use alloc::string::String;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

use crate::TypesError;
use crate::validate_nonempty_unique;

#[derive(Clone, Debug, PartialEq)]
pub struct LicenseExpr(pub SpdxExpr);

impl Eq for LicenseExpr {}

impl Hash for LicenseExpr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().hash(state);
    }
}

impl Deref for LicenseExpr {
    type Target = SpdxExpr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for LicenseExpr {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(self.0.as_ref())
    }
}

impl<'de> Deserialize<'de> for LicenseExpr {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        SpdxExpr::parse(&s)
            .map(LicenseExpr)
            .map_err(|e| DeError::custom(TypesError::LicenseParse(e)))
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct LicensePolicy {
    allowed: NonEmpty<LicenseReq>,
}

impl LicensePolicy {
    /// `allowed` must contain at least one entry, and every entry must be unique.
    pub fn try_new(allowed: Vec<LicenseReq>) -> Result<Self, TypesError> {
        let allow = validate_nonempty_unique(
            allowed,
            |req: &LicenseReq| req.to_string(),
            |dup: &LicenseReq| format!("Duplicate license requirement `{dup}`"),
        )
        .map_err(TypesError::Validation)?;
        Ok(Self { allowed: allow })
    }

    #[must_use]
    pub fn allowed(&self) -> nonempty::Iter<'_, LicenseReq> {
        self.allowed.iter()
    }

    /// Returns true if this policy explicitly allows `req`.
    #[must_use]
    pub fn contains(&self, req: &LicenseReq) -> bool {
        self.allowed.iter().any(|allowed| allowed == req)
    }
}

impl Serialize for LicensePolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_vec: Vec<String> = self.allowed.iter().map(ToString::to_string).collect();
        as_vec.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LicensePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::deserialize(deserializer)?;
        let mut out = Vec::with_capacity(raw.len());

        for s in raw {
            let expr = SpdxExpr::parse(&s).map_err(DeError::custom)?;
            let mut reqs = expr.requirements().map(|er| er.req.clone());
            let first = reqs
                .next()
                .ok_or_else(|| DeError::custom("empty SPDX expression"))?;
            if reqs.next().is_some() {
                return Err(DeError::custom(format!(
                    "`{s}` contains multiple license terms; expected exactly one"
                )));
            }
            out.push(first);
        }

        Self::try_new(out).map_err(DeError::custom)
    }
}

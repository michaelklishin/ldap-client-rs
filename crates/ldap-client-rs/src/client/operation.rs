// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::{
    AddRequest, BindRequest, BindResponse, CompareRequest, ExtendedRequest, ExtendedResponse,
    HasLdapResult, LdapOperation, LdapResult, ModifyDnRequest, ModifyRequest, ResultCode,
};

/// A request and the response that answers it. `output` decides what counts
/// as the operation's success, and hands the response back otherwise.
pub(super) trait Operation {
    type Response: HasLdapResult;
    type Output;
    const RESPONSE: &'static str;

    fn to_protocol(&self) -> LdapOperation;
    fn response(operation: LdapOperation) -> Option<Self::Response>;
    fn output(response: Self::Response) -> Result<Self::Output, Self::Response>;
}

fn success(result: LdapResult) -> Result<(), LdapResult> {
    if result.code == ResultCode::Success {
        Ok(())
    } else {
        Err(result)
    }
}

macro_rules! write_operation {
    ($request:ident, $response:ident, $name:literal) => {
        impl Operation for $request {
            type Response = LdapResult;
            type Output = ();
            const RESPONSE: &'static str = $name;

            fn to_protocol(&self) -> LdapOperation {
                LdapOperation::$request(self.clone())
            }

            fn response(operation: LdapOperation) -> Option<LdapResult> {
                match operation {
                    LdapOperation::$response(result) => Some(result),
                    _ => None,
                }
            }

            fn output(response: LdapResult) -> Result<(), LdapResult> {
                success(response)
            }
        }
    };
}

write_operation!(AddRequest, AddResponse, "AddResponse");
write_operation!(ModifyRequest, ModifyResponse, "ModifyResponse");
write_operation!(ModifyDnRequest, ModifyDnResponse, "ModifyDnResponse");

/// A delete request is a bare DN.
pub(super) struct Delete(pub(super) String);

impl Operation for Delete {
    type Response = LdapResult;
    type Output = ();
    const RESPONSE: &'static str = "DeleteResponse";

    fn to_protocol(&self) -> LdapOperation {
        LdapOperation::DeleteRequest(self.0.clone())
    }

    fn response(operation: LdapOperation) -> Option<LdapResult> {
        match operation {
            LdapOperation::DeleteResponse(result) => Some(result),
            _ => None,
        }
    }

    fn output(response: LdapResult) -> Result<(), LdapResult> {
        success(response)
    }
}

impl Operation for CompareRequest {
    type Response = LdapResult;
    type Output = bool;
    const RESPONSE: &'static str = "CompareResponse";

    fn to_protocol(&self) -> LdapOperation {
        LdapOperation::CompareRequest(self.clone())
    }

    fn response(operation: LdapOperation) -> Option<LdapResult> {
        match operation {
            LdapOperation::CompareResponse(result) => Some(result),
            _ => None,
        }
    }

    fn output(response: LdapResult) -> Result<bool, LdapResult> {
        match response.code {
            ResultCode::CompareTrue => Ok(true),
            ResultCode::CompareFalse => Ok(false),
            _ => Err(response),
        }
    }
}

impl Operation for ExtendedRequest {
    type Response = ExtendedResponse;
    type Output = ExtendedResponse;
    const RESPONSE: &'static str = "ExtendedResponse";

    fn to_protocol(&self) -> LdapOperation {
        LdapOperation::ExtendedRequest(self.clone())
    }

    fn response(operation: LdapOperation) -> Option<ExtendedResponse> {
        match operation {
            LdapOperation::ExtendedResponse(response) => Some(response),
            _ => None,
        }
    }

    fn output(response: ExtendedResponse) -> Result<ExtendedResponse, ExtendedResponse> {
        if response.result.code == ResultCode::Success {
            Ok(response)
        } else {
            Err(response)
        }
    }
}

impl Operation for BindRequest {
    type Response = BindResponse;
    type Output = ();
    const RESPONSE: &'static str = "BindResponse";

    fn to_protocol(&self) -> LdapOperation {
        LdapOperation::BindRequest(self.clone())
    }

    fn response(operation: LdapOperation) -> Option<BindResponse> {
        match operation {
            LdapOperation::BindResponse(response) => Some(response),
            _ => None,
        }
    }

    fn output(response: BindResponse) -> Result<(), BindResponse> {
        if response.result.code == ResultCode::Success {
            Ok(())
        } else {
            Err(response)
        }
    }
}

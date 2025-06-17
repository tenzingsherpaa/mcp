# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.


def handle_aws_api_error(e: Exception) -> Exception:
    """Handle common AWS API errors and return standardized error responses.

    Args:
        e: The exception that was raised
        resource_type: Optional resource type related to the error
        identifier: Optional resource identifier related to the error

    Returns:
        Standardized error response dictionary
    """
    print('performing error mapping for an AWS exception')
    error_message = str(e)
    error_type = 'UnknownError'

    # Extract error type from AWS exceptions if possible
    if hasattr(e, 'response') and 'Error' in getattr(e, 'response', {}):
        error_type = e.response['Error'].get('Code', 'UnknownError')  # pyright: ignore[reportAttributeAccessIssue]

    # Authentication/Authorization Errors
    if 'AccessDenied' in error_message or error_type == 'AccessDeniedException':
        return ClientError('Access denied. Please check your AWS credentials and permissions.')
    elif 'InvalidClientTokenId' in error_message:
        return ClientError(
            'Invalid client token id. The X.509 certificate or AWS access key ID provided does not exist in our records.'
        )
    elif 'NotAuthorized' in error_message:
        return ClientError('Not authorized. You do not have permission to perform this action.')

    # Request Validation Errors
    elif 'IncompleteSignature' in error_message:
        return ClientError(
            'Incomplete signature. The request signature does not conform to AWS standards.'
        )
    elif 'InvalidAction' in error_message:
        return ClientError(
            'Invalid action. The action or operation requested is invalid. Verify that the action is typed correctly.'
        )
    elif 'ValidationException' in error_message or error_type == 'ValidationException':
        return ClientError('Validation error. Please check your input parameters.')
    elif 'InvalidPatchException' in error_message:
        return ClientError(
            'The patch document provided contains errors or is not RFC 6902 compliant.'
        )

    # Resource Errors
    elif 'ResourceNotFoundException' in error_message or error_type == 'ResourceNotFoundException':
        return ClientError('Resource was not found')
    elif (
        'UnsupportedActionException' in error_message or error_type == 'UnsupportedActionException'
    ):
        return ClientError('This action is not supported for this resource type.')

    # Service Errors
    elif 'ThrottlingException' in error_message or error_type == 'ThrottlingException':
        return ClientError('Request was throttled. Please reduce your request rate.')
    elif 'InternalFailure' in error_message or error_type == 'InternalFailure':
        return ServerError('Internal failure. The server failed to process the request.')
    elif 'ServiceUnavailable' in error_message or error_type == 'ServiceUnavailable':
        return ServerError('Service unavailable. The server failed to process the request.')

    # Generic Error
    else:
        # Generic error handling - we might shift to this for everything eventually since it gives more context to the LLM, will have to test
        return ClientError(f'An error occurred: {error_message}')



class ClientError(Exception):
    """An error that indicates that the request was malformed or incorrect in some way. There was no issue on the server side.
    
    This error is raised when:
    - The request contains invalid parameters or data
    - Authentication/authorization fails
    - The requested resource does not exist
    - The requested action is not supported
    - Request validation fails
    """

    def __init__(self, message):
        """Initialize a new ClientError.
        
        Args:
            message (str): A descriptive error message explaining what went wrong
        """
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.type = 'client'  # Indicates this is a client-side error
        self.message = message  # Store the error message for later reference

class ServerError(Exception):
    """An error that indicates that there was an issue processing the request on the server side.
    
    This error is raised when:
    - There is an internal server failure
    - The service is temporarily unavailable
    - The server fails to process the request due to high load
    - There are infrastructure or deployment issues
    - Unexpected errors occur during request processing
    """

    def __init__(self, log):
        """Initialize a new ServerError.
        
        Args:
            log (str): A detailed error message or log that will be printed for debugging.
                      This should not be exposed to end users but is useful for troubleshooting.
        """
        # Call the base class constructor with a generic user-facing error message
        super().__init__('An internal error occurred while processing your request')
        print(log)  # Print the detailed error for debugging
        self.type = 'server'  # Indicates this is a server-side error


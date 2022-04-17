const region = { region: "us-east-1" };
const { CognitoIdentityProviderClient, AdminInitiateAuthCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');
const { toUtf8 } = require('@aws-sdk/util-utf8-node');
const idpClient = new CognitoIdentityProviderClient(region);
const lambdaClient = new LambdaClient(region);

const log4js = require('log4js');
const log = log4js.getLogger();
log.level = 'info';

const getApp = async (clientId, secret) => {
    const params = {
        FunctionName: process.env.AIMS_APPS_LAMBDA_NAME,
        Payload: JSON.stringify({ clientId, secret })
    };
    const response = await lambdaClient.send(new InvokeCommand(params));
    const payload = JSON.parse(toUtf8(response.Payload));
    if (response.FunctionError) {
        throw Error(payload.errorMessage);
    }
    return payload;
};

const generatePolicy = (effect, resource, principal, authHeader) => {
    const authResponse = { principalId: principal };
    if (effect && resource) {
        authResponse.policyDocument = {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource,
            }]
        };
    }
    authResponse.context = {
        'X-App-Authorization': authHeader,
    };
    return authResponse;
};

const getIdToken = async (username, password, clientId) => {
    const params = {
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        UserPoolId: process.env.COGNITO_POOL_ID,
        ClientId: clientId,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
        },
    };
    const data = await idpClient.send(new AdminInitiateAuthCommand(params));
    return data.AuthenticationResult.IdToken;
};

module.exports.handler = async (event, context, callback) => {
    try {
        const b64auth = (event.headers.Authorization || '').split(' ')[1] || '';
        const [clientId, secret] = Buffer.from(b64auth, 'base64').toString().split(':');
        const { sourceIp } = event.requestContext.identity;
        const app = await getApp(clientId, secret);

        if (app.isWhiteListActive && app.whiteList && app.whiteList.length && !app.whiteList.includes(sourceIp)) {
            callback('Unauthorized', null);
        }

        const token = await getIdToken(app.username, secret, clientId);
        const policy = generatePolicy('Allow', event.methodArn, app.username, token);
        callback(null, policy);
    } catch (e) {
        log.error(e.message + '. Event: ' + JSON.stringify(event));
        callback('Unauthorized', null);
    }
}

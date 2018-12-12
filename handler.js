'use strict'

const AWS = require('aws-sdk')
const { promisify } = require('util')
const dynamoDb = new AWS.DynamoDB.DocumentClient()
const jwt = require('jsonwebtoken')
let { hash, compare } = require('bcryptjs')
hash = promisify(hash)
compare = promisify(compare)

const createToken = params => jwt.sign(params, 'secret', {
  expiresIn: 86400
})

const createPolicy = (principalId, resource) => {
  const authResponse = {}
  authResponse.principalId = principalId
  const policyDocument = {}
  policyDocument.Version = '2012-10-17'
  policyDocument.Statement = []
  const statementOne = {}
  statementOne.Action = 'execute-api:Invoke'
  statementOne.Effect = 'Allow'
  statementOne.Resource = resource
  policyDocument.Statement[0] = statementOne
  authResponse.policyDocument = policyDocument
  return authResponse
}

module.exports.auth = (event, context, callback) => {
  const token = event.authorizationToken
  if (!token) {
    callback(new Error('Unauthorized'))
  } else {
    let decoded
    try {
      decoded = jwt.verify(token, 'secret')
    } catch (error) {
      callback(new Error('Unauthorized'))
      return
    }
    console.log('decoded', decoded)
    console.log('methodArn', event.methodArn)
    callback(null, createPolicy(decoded.username, event.methodArn))
  }
}

module.exports.account = async (event, context) => {
  return {
    body: 'account',
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*'
    }
  }
}

module.exports.login = async (event, context) => {
  try {
    const { username, password } = JSON.parse(event.body)
    const user = await dynamoDb
      .get({
        TableName: 'users',
        Key: { username }
      })
      .promise()
    const userExists = Object.keys(user).length > 0
    if (userExists) {
      const correctPassword = user.Item.password
      const success = await compare(password, correctPassword)
      if (success) {
        const token = createToken({ username })
        return {
          statusCode: 201,
          body: JSON.stringify({ token }),
          headers: {
            'Access-Control-Allow-Origin': '*'
          }
        }
      }
    }
    return {
      statusCode: 400,
      body: '',
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    }
  } catch (error) {
    console.error('error', error)
    return {
      headers: {},
      statusCode: 500,
      body: ''
    }
  }
}

module.exports.register = async (event, context) => {
  try {
    const { username, password } = JSON.parse(event.body)
    const user = await dynamoDb
      .get({
        TableName: 'users',
        Key: { username }
      })
      .promise()
    const userAlreadyExists = Object.keys(user).length > 0
    if (userAlreadyExists) {
      return {
        statusCode: 409,
        body: '',
        headers: {
          'Access-Control-Allow-Origin': '*'
        }
      }
    } else {
      await dynamoDb.put({
        TableName: 'users',
        Item: {
          username,
          password: await hash(password, 8)
        }
      }).promise()
      const token = createToken({ username })
      return {
        statusCode: 201,
        body: JSON.stringify({ token }),
        headers: {
          'Access-Control-Allow-Origin': '*'
        }
      }
    }
  } catch (error) {
    console.error('error', error)
    return {
      headers: {},
      statusCode: 500,
      body: ''
    }
  }
}

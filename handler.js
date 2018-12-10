'use strict'

const AWS = require('aws-sdk')
const { promisify } = require('util')
const dynamoDb = new AWS.DynamoDB.DocumentClient()
let { hash } = require('bcryptjs')
hash = promisify(hash)
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
      return {
        statusCode: 201,
        body: '',
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

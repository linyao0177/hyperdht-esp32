const eth = require('./lib/eth')
const did = require('./lib/did')
const reading = require('./lib/reading')
const seller = require('./lib/seller')
const owner = require('./lib/owner')

module.exports = { ...did, ...reading, ...seller, ...owner, eth }

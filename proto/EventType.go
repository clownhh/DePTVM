package proto

// AP register event
const AP_REGISTER = 1

// reply to AP register request(OA)
const AP_REGISTER_REPLY_OA = 2

// reply to AP register request(CSP)
const AP_REGISTER_REPLY_CSP = 3

const OA_REGISTER_CSP = 4

const OA_REGISTER_OAS = 5

const OA_REGISTER_REPLY_CSP = 6

// register UE request to AP
const UE_REGISTER_APSIDE = 7

// register UE request to OA
const UE_REGISTER_OASIDE = 8

// confirmation for successfully registering UE
const UE_REGISTER_CONFIRMATION = 9

// announce phase event
const FORWARD_SHUFFLE = 10

// synchronize reputation map among servers when initial list generated and make the genesis block
const SYNC_REPMAP = 11

//OA send data require request to CSP
const DATA_COLLECTION_AP = 12

//collect the trust value data from CSP to OA
const DATA_COLLECTION_OA = 13

//publish the block to OAs
const RECEIVE_BLOCK = 14

// round end event
const REVERSE_SHUFFLE = 15

//unique list confirmation
const UNIQUE_LIST_CONFIRMATION = 16

//const READY_FOR_MINE = 17

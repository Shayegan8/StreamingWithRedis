import net from 'net'
import crypto from 'crypto'
import { exit } from 'process'
import { Redis } from 'ioredis'
import PQueue from 'p-queue'
import config from '../config.json' with { type: 'json' }

const conn = new Redis(config.connstring, {
    maxRetriesPerRequest: null,
    tls: { servername: config.servername }
})

function logger(param: string, type?: string) {
    console.log(type == "info" ? `[\x1b[33mINFO\x1b[0m] ${param}`
        : (type == "error" ? `[\x1b[31mERR\x1b[0m] ${param}` : param))
}

const connlist = new Map<string, any>()

const server = net.createServer((socket) => {
    socket.on('error', (err) => {
        logger(`Client error: ${err.message}`, "error")
    })
    socket.once('data', (data1: Buffer) => {
        if (data1[0] != 0x05)
            return socket.end()
        const packet_l = data1.length
        if (packet_l >= 3) { // VER
            const reply = Buffer.alloc(2)
            reply[0] = 0x05 // VER
            reply[1] = 0x00 // NO AUTHENTICATION REQUIRED ONLY
            socket.write(reply)
            logger("sub-negotiation finished", "info")
        }
        socket.once('data', async (data: Buffer) => {
            if (data[2] == 0x00 && data.length >= 10) { // we got rsv before gta6
                // DST.ADDR, DST.PORT
                let DSTADDR: string
                let DSTPORT
                let portOffset
                let addressLength
                // data transfering between proxy and application server happnes here
                switch (data[3]) { // ATYP
                    case 0x01: // IPv4
                        DSTADDR = [data[4], data[5], data[6], data[7]].join('.')
                        portOffset = 8
                        addressLength = 4
                        break
                    case 0x03: // DOMAINNAME
                        const numberOfBytes = data.readUInt8(4)
                        DSTADDR = data.subarray(5, 5 + numberOfBytes).toString()
                        portOffset = 5 + numberOfBytes
                        addressLength = numberOfBytes
                        break
                    case 0x04: // IPv6
                        let IPv6: string[] = []
                        for (let i = 4; i < 20; i += 2)
                            IPv6.push(data.readUInt16BE(i).toString(16))
                        DSTADDR = IPv6.join(':')
                        portOffset = 20
                        addressLength = 16
                        break
                    default:
                        return
                }
                DSTPORT = data.readUInt16BE(portOffset)
                const ATYP = data[3]
                logger(`ATYP: ${Buffer.from(ATYP.toString()).toString('binary')}, Address: ${DSTADDR}:${DSTPORT}`, "info")
                logger(`CMD: ${Buffer.from(data[1]!.toString()).toString('binary')}`, "info")
                switch (data[1]) { // cmd
                    case 0x01: // CONNECT
                        let connectionID = crypto.randomUUID()
                        logger("FUCKING ID " + connectionID)
                        await conn.lpush(`inform`, `${DSTADDR},${DSTPORT},${connectionID}`)

                        let pqueue = new PQueue({ concurrency: 1 })
                        let buff: Buffer[] = []
                        socket.on('data', (data: Buffer) => {
                            pqueue.add(() => {
                                buff.push(data)
                                length += data.length
                                connlist.set(connectionID, {})
                            })
                        })

                        let length = 0
                        const interv = setInterval(async () => {
                            pqueue.add(async () => {
                                if (length > 1024 * 500) {
                                    logger("The generated reqID ")
                                    conn.lpush(`proxy,${connectionID}`, Buffer.concat(buff))
                                    connlist.set(connectionID, true)
                                    buff = []
                                    logger("Added? " + `proxy,${connectionID}`)
                                    length = 0
                                    return
                                }
                                if (length != buff.length)
                                    length = buff.length
                                else {
                                    if (buff.length != 0) {
                                        logger("it means there?")
                                        length = 0
                                        logger("The generated reqID ")
                                        connlist.set(connectionID, true)
                                        conn.lpush(`proxy,${connectionID}`, Buffer.concat(buff))
                                        buff = []
                                        logger("Added? " + `proxy,${connectionID}`)
                                        logger("What is the length now?" + buff.length)
                                    }
                                }
                            })
                        }, 100)

                        socket.on('end', () => {
                            conn.lpush(`proxy,${connectionID}`, Buffer.from('end', 'binary'))
                            clearInterval(pinger)
                            blconn.disconnect()
                            connlist.delete(connectionID)
                            clearInterval(interv)
                        })

                        logger("connection once")
                        const server_reply = Buffer.alloc(10)
                        server_reply[0] = 0x05 // VER
                        server_reply[1] = 0x00 // REP
                        server_reply[2] = 0x00 // RSV
                        server_reply[3] = 0x01
                        // dummy bound address, its tough to receive this
                        server_reply[4] = 0
                        server_reply[5] = 0
                        server_reply[6] = 0
                        server_reply[7] = 0
                        // dummy port
                        server_reply[8] = 0
                        server_reply[9] = 0
                        socket.write(server_reply)
                        logger(`CONNECT done for ${connectionID}`, "info")
                        const blconn = new Redis(config.connstring, {
                            maxRetriesPerRequest: null,
                            tls: { servername: config.servername }
                        })
                        const pinger = setInterval(async () => {
                            await blconn.ping()
                        }, 10000)

                        while (true) {
                            try {
                                const response = await blconn.brpopBuffer(`appserver,${connectionID}`, 0)
                                if (!response) {
                                    logger(`end for ${connectionID} from targetServer`)
                                    clearInterval(pinger)
                                    blconn.disconnect()
                                    socket.end()
                                    await conn.del(`appserver,${connectionID}`)
                                    break
                                }

                                logger(`this mf got fucking called, ${connectionID}`)
                                if (!Buffer.from('end', 'binary').compare(response![1])) {
                                    logger(`response for ${connectionID} is null ;(`)
                                    clearInterval(pinger)
                                    blconn.disconnect()
                                    socket.end()
                                    await conn.del(`appserver,${connectionID}`)
                                    break
                                }
                                socket.write(response![1])
                            } catch (error) {
                                logger(`handling a job that no longer exist, ${connectionID}`, "error")
                            }
                        }
                        break
                    default:
                        break
                }
            }
        })
    })
})

setInterval(async () => {
    conn.ping()
}, 10000)

process.on('SIGTERM', () => {
    for (const element of connlist.keys())
        conn.del(`appserver,${element}`)
    exit(0)
})

process.on('SIGINT', () => {
    for (const element of connlist.keys())
        conn.del(`proxy,${element}`)

    server.close()
    exit(0)
})

logger("Listening on 1080", "info")
server.listen(1080)

server.on('error', (error) => {
    logger(`Problem with connection with application server ${error.message}`, "error")
})
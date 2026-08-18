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

try {
    conn.ping()
} catch (e) {
    logger("conn ping error: " + e, "error")
}

function logger(param: string, type?: string) {
    const date = new Date(Date.now())
    console.log(type == "info" ? `[\x1b[33mINFO\x1b[0m] ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()} ${param}`
        : (type == "error" ? `[\x1b[31mERR\x1b[0m] ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()} ${param}` : param))
}

const connlist = new Map<string, any>()

const symmetricKey = Buffer.from(config.symmetricKey, "hex")

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
        }
        socket.once('data', async (data: Buffer) => {
            if (data[2] == 0x00 && data.length >= 10) {
                // DST.ADDR, DST.PORT
                let DSTADDR: string
                let DSTPORT
                let portOffset
                switch (data[3]) { // ATYP
                    case 0x01: // IPv4
                        DSTADDR = [data[4], data[5], data[6], data[7]].join('.')
                        portOffset = 8
                        break
                    case 0x03: // DOMAINNAME
                        const numberOfBytes = data.readUInt8(4)
                        DSTADDR = data.subarray(5, 5 + numberOfBytes).toString()
                        portOffset = 5 + numberOfBytes
                        break
                    case 0x04: // IPv6
                        let IPv6: string[] = []
                        for (let i = 4; i < 20; i += 2)
                            IPv6.push(data.readUInt16BE(i).toString(16))
                        DSTADDR = IPv6.join(':')
                        portOffset = 20
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
                        logger("Informing for " + connectionID, "info")
                        const msg = Buffer.from(`${DSTADDR},${DSTPORT},${connectionID}`, 'binary')
                        const iv = crypto.randomBytes(12)
                        const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                        const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                        const tag = cipher.getAuthTag()
                        await conn.lpush(`inform`, Buffer.concat([iv, tag, encryptedMsg]))

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
                                    logger(`Pushing BIG batch to proxy,${connectionID}`, "info")
                                    const msg = Buffer.concat(buff)
                                    const iv = crypto.randomBytes(12)
                                    const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                                    const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                                    const tag = cipher.getAuthTag()

                                    await conn.lpush(`proxy,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                                    connlist.set(connectionID, true)
                                    buff = []
                                    length = 0
                                    return
                                }
                                if (length != buff.length)
                                    length = buff.length
                                else {
                                    if (buff.length != 0) {
                                        length = 0
                                        connlist.set(connectionID, true)
                                        logger(`Pushing batch to proxy,${connectionID}`, "info")
                                        const msg = Buffer.concat(buff)
                                        const iv = crypto.randomBytes(12)
                                        const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                                        const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                                        const tag = cipher.getAuthTag()
                                        await conn.lpush(`proxy,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                                        buff = []
                                    }
                                }
                            })
                        }, 100)

                        socket.once('error', (e) => {
                            logger(`Client error: ${e}`, "error")
                            clearInterval(pinger)
                            clearInterval(interv)
                            blconn.quit()
                            connlist.delete(connectionID)
                        })

                        socket.on('end', async () => {
                            logger(`Sending half close signal to proxy,${connectionID}`, "info")
                            const msg = Buffer.from('end', 'binary')
                            const iv = crypto.randomBytes(12)
                            const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                            const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                            const tag = cipher.getAuthTag()
                            await conn.lpush(`proxy,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                            clearInterval(pinger)
                            clearInterval(interv)
                            blconn.quit()
                            connlist.delete(connectionID)
                        })

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
                        logger(`CONNECT done for ${connectionID} with ${DSTADDR} destination`, "info")
                        const blconn = new Redis(config.connstring, {
                            maxRetriesPerRequest: null,
                            tls: { servername: config.servername }
                        })

                        try {
                            blconn.ping()
                        } catch (e) {
                            logger("blconn ping error: " + e, "error")
                            clearInterval(interv)
                            socket.end()
                            connlist.delete(connectionID)
                        }
                        const pinger = setInterval(async () => {
                            try {
                                await blconn.ping()
                            } catch (e) {
                                logger("pinger: " + e, "info")
                                clearInterval(pinger)
                                clearInterval(interv)
                                socket.end()
                                connlist.delete(connectionID)
                            }
                        }, 10000)
                        while (true) {
                            try {
                                const response = await blconn.brpopBuffer(`appserver,${connectionID}`, 0)
                                if (!response) {
                                    logger(`end for ${connectionID} from targetServer`, "info")
                                    await conn.del(`appserver,${connectionID}`)
                                    clearInterval(pinger)
                                    clearInterval(interv)
                                    blconn.quit()
                                    connlist.delete(connectionID)
                                    socket.end()
                                    break
                                }
                                const extractIv = response[1].subarray(0, 12)
                                const tag = response[1].subarray(12, 28)
                                const encryptedChunk = response[1].subarray(28)
                                const decipher = crypto.createDecipheriv("aes-256-gcm", symmetricKey, extractIv)
                                decipher.setAuthTag(tag)
                                const decryptedChunk = Buffer.concat([decipher.update(encryptedChunk), decipher.final()])
                                if (!Buffer.from('end', 'binary').compare(decryptedChunk)) {
                                    logger(`server chunk for ${connectionID} is null`, "info")
                                    clearInterval(pinger)
                                    clearInterval(interv)
                                    blconn.quit()
                                    connlist.delete(connectionID)
                                    socket.end()
                                    await conn.del(`appserver,${connectionID}`)
                                    break
                                }
                                socket.write(decryptedChunk)
                            } catch (error) {
                                clearInterval(pinger)
                                clearInterval(interv)
                                connlist.delete(connectionID)
                                socket.end()
                                break
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
    try {
        conn.ping()
    } catch (e) {
        logger("gPinger: " + e, "info")
    }
}, 10000)

process.on('uncaughtException', (error) => {
    logger(`Uncaught exception ${error}`, "error")
})

process.on('SIGTERM', async () => {
    logger("Stopping the server", "info")
    server.close()
    await conn.del("inform")
    for (const element of connlist.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})

process.on('SIGINT', async () => {
    logger("Stopping the server", "info")
    server.close()
    await conn.del("inform")
    for (const element of connlist.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})

logger("Listening on 1080", "info")
server.listen(1080)

server.on('error', (error) => {
    logger(`Problem with connection with application server ${error.message}`, "error")
})
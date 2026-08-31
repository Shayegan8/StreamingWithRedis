import net, { Socket } from 'net'
import dns from 'dns/promises'
import { Redis } from 'ioredis'
import { exit } from 'process'
import PQueue from 'p-queue'
import crypto from 'node:crypto'
import config from '../config.json' with { type: 'json' }

const conn = new Redis(config.connstring, {
    maxRetriesPerRequest: null,
    tls: { servername: config.servername }
})
try {
    await conn.ping()
} catch (e) {
    logger("conn ping error: " + e, "error")
}

const blconn = new Redis(config.connstring, {
    maxRetriesPerRequest: null,
    tls: { servername: config.servername }
})

try {
    await blconn.ping()
} catch (e) {
    logger("blconn ping error: " + e, "error")
}

function logger(param: string, type?: string) {
    const date = new Date(Date.now())
    console.log(type == "info" ? `[\x1b[33mINFO\x1b[0m] ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()} ${param}`
        : (type == "error" ? `[\x1b[31mERR\x1b[0m] ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()} ${param}` : param))
}

//DNS RESOLVE, for now its not optimized but works atleast
const workingDNSes = new Map<string, { ip: string, requiredTime: number }>() // Map<address, ip>
let fastestDNSes = new Map<string, { ip: string, requiredTime: number }>() //Map<address, fastest ip>

const symmetricKey = Buffer.from(config.symmetricKey, "hex")

async function testConnection(address: string, ip: string, port: number): Promise<boolean> {
    return await new Promise<boolean>((resolve) => {
        const startTime = Date.now()
        const connection = net.createConnection(port!, ip)
        const timeo = setTimeout(() => {
            connection.destroy()
            resolve(false)
        }, 3000)
        connection.on('connect', () => {
            clearTimeout(timeo)
            workingDNSes.set(address, { ip: ip, requiredTime: Date.now() - startTime })
            resolve(true)
        })
        connection.on('error', () => {
            clearTimeout(timeo)
            connection.destroy()
            resolve(false)
        })
    })
}

async function getFastestIP(address: string, port: number): Promise<string | null> {
    if (fastestDNSes.has(address))
        return fastestDNSes.get(address)!.ip
    try {
        const ipv4s = (await dns.resolve(address)).filter(x => x.includes('.'))
        if (ipv4s.length == 0)
            return null
        for (const ipv4 of ipv4s) {
            await testConnection(address, ipv4, port)
        }
        fastestDNSes = new Map([...workingDNSes.entries()].sort((a, b) => a[1].requiredTime - b[1].requiredTime))
        return fastestDNSes.get(address)?.ip || null
    } catch (err) {
        return null
    }
}

const sockets = new Map<string, Socket>()
setImmediate(async () => {
    while (true) {
        logger("Waiting for inform", "info")
        const payload = await blconn.brpopBuffer(`inform`, 0)
        const extractIv = payload![1].subarray(0, 12)
        const tag = payload![1].subarray(12, 28)
        const encryptedChunk = payload![1].subarray(28)
        const decipher = crypto.createDecipheriv("aes-256-gcm", symmetricKey, extractIv)
        decipher.setAuthTag(tag)
        const decryptedChunk = Buffer.concat([decipher.update(encryptedChunk), decipher.final()])

        const things = decryptedChunk.toString('utf8').split(',')!
        const dstaddr = things[0]!
        const dstport = parseInt(things[1]!)
        const connectionID = things[2]!
	const atyp = things[3]!
        logger(`Waiting for proxy,${connectionID}`, "info")
        setImmediate(async () => {
            try {
                const blconn1 = new Redis(config.connstring, {
                    maxRetriesPerRequest: null,
                    tls: { servername: config.servername }
                })

                blconn1.on('error', () => {
                    logger("blconn error event: " + connectionID, "error")
                    clearInterval(pinger)
                    sockets.get(connectionID)?.end()
                    sockets.delete(connectionID)
                })

                try {
                    await blconn1.ping()
                } catch (e) {
                    logger("blconn1 ping error: " + e, "error")
                    return
                }

                const pinger = setInterval(async () => {
                    try {
                        await blconn1.ping()
                    } catch (e) {
                        logger("pinger: " + e, "info")
                        clearInterval(pinger)
                        sockets.delete(connectionID)
                    }
                }, 10000)

                while (true) {
                    const request = (await blconn1.brpopBuffer(`proxy,${connectionID}`, 0))?.[1]
                    if (!request) {
                        logger("proxy chunk is null for " + connectionID, "error")
                        clearInterval(pinger)
                        blconn1.quit()
                        sockets.delete(connectionID)
                        break
                    }
                    const extractIv = request.subarray(0, 12)
                    const tag = request.subarray(12, 28)
                    const encryptedChunk = request.subarray(28)
                    const decipher = crypto.createDecipheriv("aes-256-gcm", symmetricKey, extractIv)
                    decipher.setAuthTag(tag)
                    const decryptedChunk = Buffer.concat([decipher.update(encryptedChunk), decipher.final()])

                    if (!Buffer.from('end', 'binary').compare(decryptedChunk)) {
                        logger("breaking the " + connectionID, "info")
                        sockets.delete(connectionID)
                        clearInterval(pinger)
                        blconn1.quit()
                        break
                    }
                    if (!sockets.has(connectionID)) {
                        let fastestWorkingIP: string | null
			if atyp == "3"
			    fastestWorkingIP = await getFastestIP(dstaddr, dstport)
			else
			    fastestWorkingIP = dstaddr
                        if (!fastestWorkingIP) {
                            logger(`There is no working DNS for ${dstaddr} with ${connectionID} ID`, "error")
                            const msg = Buffer.from('end', 'binary')
                            const iv = crypto.randomBytes(12)
                            const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                            const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                            const tag = cipher.getAuthTag()
                            await conn.lpush(`appserver,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                            clearInterval(pinger)
                            blconn1.quit()
                            sockets.delete(connectionID)
                            break
                        }
                        const appServer = net.createConnection(dstport, fastestWorkingIP)
                        sockets.set(connectionID, appServer)
                        const res = await new Promise<Boolean>((resolve) => {
                            const connectionTimeout = setTimeout(() => {
                                logger("Timeout for " + connectionID, "error")
                                if (appServer)
                                    appServer.destroy()
                                resolve(false)
                            }, 25000)
                            appServer.once('connect', async () => {
                                clearTimeout(connectionTimeout)
                                logger(connectionID + " connected", "info")
                                resolve(true)
                            })
                            appServer.once('error', () => {
                                clearTimeout(connectionTimeout)
                                logger(`Can't reach ${dstaddr}:${dstport}`, "error")
                                if (appServer)
                                    appServer.destroy()
                                resolve(false)
                            })
                        })
                        if (!res) {
                            clearInterval(pinger)
                            sockets.delete(connectionID)
                            blconn1.quit()
                            break
                        }

                        sockets.get(connectionID)?.write(decryptedChunk)
                        let buffass: Buffer[] = []
                        let timeout: NodeJS.Timeout
                        let pqueue = new PQueue({ concurrency: 1 })
                        let length = 0
                        appServer.on('data', (data: Buffer) => {
                            pqueue.add(() => {
                                if (timeout)
                                    clearTimeout(timeout)
                                length += data.length
                                buffass.push(data)
                                pqueue.add(async () => {
                                    if (length > 1024 * 1024 * 2) { // bigger than 2mb
                                        logger(`Pushing BIG batch to appserver,${connectionID}`, "info")
                                        const msg = Buffer.concat(buffass)
                                        const iv = crypto.randomBytes(12)
                                        const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                                        const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                                        const tag = cipher.getAuthTag()
                                        await conn.lpush(`appserver,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                                        buffass = []
                                        length = 0
                                    }
                                })
                                timeout = setTimeout(() => {
                                    if (!length)
                                        return
                                    pqueue.add(async () => {
                                        logger(`Pushing batch to appserver,${connectionID}`, "info")
                                        const msg = Buffer.concat(buffass)
                                        const iv = crypto.randomBytes(12)
                                        const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                                        const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                                        const tag = cipher.getAuthTag()
                                        await conn.lpush(`appserver,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                                        buffass = []
                                        length = 0
                                    })
                                }, 100)
                            })
                        })
                        // notify the proxy appserver dont sends data anymore (half close)
                        appServer.on('end', async () => {
                            logger(`Sending half close signal to appserver,${connectionID}`, "info")
                            const msg = Buffer.from('end', 'binary')
                            const iv = crypto.randomBytes(12)
                            const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv)
                            const encryptedMsg = Buffer.concat([cipher.update(msg), cipher.final()])
                            const tag = cipher.getAuthTag()
                            await conn.lpush(`appserver,${connectionID}`, Buffer.concat([iv, tag, encryptedMsg]))
                            clearInterval(pinger)
                            blconn1.quit()
                            sockets.delete(connectionID)
                        })
                    } else
                        sockets.get(connectionID)?.write(decryptedChunk)
                }
            } catch (e) {
            }
        })
    }
})

setInterval(async () => {
    try {
        await conn.ping()
        await blconn.ping()
    } catch (e) {
        logger("gPinger: " + e, "info")
    }
}, 10000)

process.on('uncaughtException', (error) => {
    logger(`Uncaught exception ${error}`, "error")
})

process.on('SIGTERM', async () => {
    logger("Stopping the server", "info")
    await conn.del("inform")
    for (const element of sockets.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})

process.on('SIGINT', async () => {
    logger("Stopping the server", "info")
    await conn.del("inform")
    for (const element of sockets.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})

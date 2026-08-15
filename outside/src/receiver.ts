import net, { Socket } from 'net'
import dns from 'dns/promises'
import { Redis } from 'ioredis'
import { exit } from 'process'
import PQueue from 'p-queue'

import config from '../config.json' with { type: 'json' }

const conn = new Redis(config.connstring, {
    maxRetriesPerRequest: null,
    tls: { servername: config.servername }
})

conn.ping()

const blconn = new Redis(config.connstring, {
    maxRetriesPerRequest: null,
    tls: { servername: config.servername }
})

blconn.ping()

function logger(param: string, type?: string) {
    console.log(type == "info" ? `[\x1b[33mINFO\x1b[0m] ${param}`
        : (type == "error" ? `[\x1b[31mERR\x1b[0m] ${param}` : param))
}

//DNS RESOLVE, for now its not optimized but works atleast
const workingDNSes = new Map<string, { ip: string, requiredTime: number }>() // Map<address, ip>
let fastestDNSes = new Map<string, { ip: string, requiredTime: number }>() //Map<address, fastest ip>

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
        const payload = await blconn.blpop(`inform`, 0)
        logger(`${payload}`)
        const things = payload?.[1].split(',')!
        const dstaddr = things[0]!
        const dstport = parseInt(things[1]!)
        const connectionID = things[2]!
        logger(`Waiting for proxy,${connectionID}`, "info")
        setImmediate(async () => {
            try {
                const blconn1 = new Redis(config.connstring, {
                    maxRetriesPerRequest: null,
                    tls: { servername: config.servername }
                })
                blconn1.ping()
                const pinger = setInterval(async () => {
                    try {
                        await blconn1.ping()
                    } catch (e) {
                        logger("pinger: " + e, "info")
                        clearInterval(pinger)
                    }
                }, 10000)

                while (true) {
                    const request = (await blconn1.brpopBuffer(`proxy,${connectionID}`, 0))?.[1]
                    logger("What 3 is request\n" + request![1])
                    if (!request) {
                        logger("proxy chunk is null for " + connectionID, "error")
                        clearInterval(pinger)
                        blconn1.disconnect()
                        sockets.delete(connectionID)
                        break
                    } else if (!Buffer.from('end', 'binary').compare(request)) {
                        logger("breaking the " + connectionID, "info")
                        sockets.delete(connectionID)
                        clearInterval(pinger)
                        blconn1.disconnect()
                        break
                    }
                    if (!sockets.has(connectionID)) {
                        const fastestWorkingIP = await getFastestIP(dstaddr, dstport)
                        if (!fastestWorkingIP) {
                            logger(`There is no working DNS for ${dstaddr} with ${connectionID} ID`, "error")
                            await conn.lpush(`appserver,${connectionID}`, Buffer.from('end', 'binary'))
                            clearInterval(pinger)
                            blconn1.disconnect()
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
                            blconn1.disconnect()
                            break
                        }

                        sockets.get(connectionID)?.write(request)
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
                                        await conn.lpush(`appserver,${connectionID}`, Buffer.concat(buffass))
                                        buffass = []
                                        length = 0
                                    }
                                })
                                timeout = setTimeout(() => {
                                    if (!length)
                                        return
                                    pqueue.add(async () => {
                                        logger(`Pushing batch to appserver,${connectionID}`, "info")
                                        await conn.lpush(`appserver,${connectionID}`, Buffer.concat(buffass))
                                        buffass = []
                                        length = 0
                                    })
                                }, 100)
                            })
                        })

                        // notify the proxy appserver dont sends data anymore (half close)
                        appServer.on('end', async () => {
                            logger(`Sending half close signal to appserver,${connectionID}`, "info")
                            await conn.lpush(`appserver,${connectionID}`, Buffer.from('end', 'binary'))
                            clearInterval(pinger)
                            blconn1.disconnect()
                            sockets.delete(connectionID)
                        })
                    } else
                        sockets.get(connectionID)?.write(request)
                }
            } catch (e) {
                logger(`${e}`)
            }
        })
    }
})

setInterval(async () => {
    try {
        conn.ping()
        blconn.ping()
    } catch (e) {
        logger("gPinger: " + e, "info")
    }
}, 10000)

process.on('SIGTERM', async () => {
    logger("Stopping the server", "info")
    for (const element of sockets.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})

process.on('SIGINT', async () => {
    logger("Stopping the server", "info")
    for (const element of sockets.keys()) {
        await conn.del(`proxy,${element}`)
        await conn.del(`appserver,${element}`)
    }
    logger("Removing chunks completed", "info")
    exit(0)
})
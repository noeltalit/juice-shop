/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const url = parseHttpUrl(req.body.imageUrl)
        // Never let the server request (or link to) loopback, private or link-local hosts
        if (url !== null && !isInternalHost(url)) {
          let profileImage: string | undefined = url.href
          try {
            const response = await downloadImage(url)
            if (response.statusCode !== 200 || !String(response.headers['content-type'] ?? '').toLowerCase().startsWith('image/')) {
              response.resume()
              throw new Error('url did not return an image')
            }
            const lastSegment = url.pathname.split('.').slice(-1)[0].toLowerCase()
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(lastSegment) ? lastSegment : 'jpg'
            await pipeline(response, fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' }))
            profileImage = `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'EBLOCKED') {
              profileImage = undefined
              logger.warn(`Refused user profile image from an internal address: ${url.hostname}`)
            } else {
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            }
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            if (profileImage !== undefined) await user?.update({ profileImage })
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

function parseHttpUrl (value: unknown) {
  if (typeof value !== 'string') return null
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : null
  } catch {
    return null
  }
}

// Loopback, private, link-local (cloud metadata), CGNAT, multicast/reserved ranges
// and their IPv6 forms; BlockList matches IPv4-mapped IPv6 (::ffff:a.b.c.d) against the IPv4 rules
const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [['::', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  return family === 0 || blockedAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

function isInternalHost (url: URL) {
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (net.isIP(host) !== 0) return isBlockedAddress(host)
  return host === 'localhost' || host.endsWith('.localhost')
}

// Resolves the host and lets the socket connect only to the addresses that were checked (no DNS rebinding)
const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) { callback(err, ''); return }
    if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
      callback(Object.assign(new Error('Image URL resolves to an internal address'), { code: 'EBLOCKED' }), '')
      return
    }
    if (options.all) callback(null, addresses)
    else callback(null, addresses[0].address, addresses[0].family)
  })
}

async function downloadImage (url: URL) {
  return await new Promise<http.IncomingMessage>((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http
    // http(s).get never follows redirects, so a public URL cannot bounce to an internal one
    client.get(url, { lookup: safeLookup, signal: AbortSignal.timeout(4000) }, resolve).on('error', reject)
  })
}

/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json({ captchaId, captcha: expression })
  }
}

// Minimum time between two accepted feedbacks per client: nobody can get 10 past the CAPTCHA within 20 seconds,
// while a single (human) submission is never blocked by earlier failed attempts
const minFeedbackIntervalMs = 2250
const lastAcceptedFeedback = new Map<string, number>()

export const resetFeedbackThrottle = () => { lastAcceptedFeedback.clear() }

export const throttleFeedback = () => (req: Request, res: Response, next: NextFunction) => {
  const client = req.socket.remoteAddress ?? ''
  const now = Date.now()
  if (now - (lastAcceptedFeedback.get(client) ?? 0) < minFeedbackIntervalMs) {
    res.status(429).send(res.__('Too many feedback submissions. Please try again in a few seconds.'))
    return
  }
  if (lastAcceptedFeedback.size > 10000) lastAcceptedFeedback.clear()
  lastAcceptedFeedback.set(client, now)
  next()
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    // Each CAPTCHA allows exactly one attempt, so it can be neither replayed nor brute-forced
    const consumed = await CaptchaModel.destroy({ where: { captchaId: req.body.captchaId } }) === 1
    if ((captcha != null) && consumed && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}

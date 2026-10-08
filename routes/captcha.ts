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
    // The plain-text expression is machine-solvable anyway, so hiding the answer adds no protection;
    // keep the API contract (clients and tests read it) and enforce the real control: single use + throttling
    res.json(captcha)
  }
}

// At most 9 feedbacks may pass the CAPTCHA per client within any 20 second window, so 10 or more within
// 20 seconds (automated submission) is impossible, while a few legitimate submissions in a row still go through
const feedbackWindowMs = 20000
const maxFeedbacksPerWindow = 9
const acceptedFeedbacks = new Map<string, number[]>()

export const resetFeedbackThrottle = () => { acceptedFeedbacks.clear() }

export const throttleFeedback = () => (req: Request, res: Response, next: NextFunction) => {
  const client = req.socket.remoteAddress ?? ''
  const now = Date.now()
  const recent = (acceptedFeedbacks.get(client) ?? []).filter(time => now - time <= feedbackWindowMs)
  if (recent.length >= maxFeedbacksPerWindow) {
    acceptedFeedbacks.set(client, recent)
    res.set('Retry-After', String(Math.max(1, Math.ceil((recent[0] + feedbackWindowMs + 1 - now) / 1000))))
    res.status(429).send(res.__('Too many feedback submissions. Please try again in a few seconds.'))
    return
  }
  if (acceptedFeedbacks.size > 10000) acceptedFeedbacks.clear()
  recent.push(now)
  acceptedFeedbacks.set(client, recent)
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

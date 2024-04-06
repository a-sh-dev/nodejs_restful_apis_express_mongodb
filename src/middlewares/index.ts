import express from 'express'
import { get, merge } from 'lodash'
import { getUserBySessionToken } from '../db/users'
import { COOKIE_AUTH } from '../constants'

export const isAuthenticated = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  try {
    const sessionToken = req.cookies[COOKIE_AUTH]
    if (!sessionToken) {
      return res.sendStatus(403)
    }

    const existingUserWithSession = await getUserBySessionToken(sessionToken)
    if (!existingUserWithSession) {
      return res.sendStatus(403)
    }

    merge(req, { identity: existingUserWithSession })

    return next()
  } catch (error) {
    console.log(error)
    return res.sendStatus(400)
  }
}

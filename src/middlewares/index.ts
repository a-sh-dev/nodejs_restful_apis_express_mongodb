import express from 'express'
import { get, merge } from 'lodash'
import { getUserBySessionToken } from '../db/users'
import { COOKIE_AUTH } from '../constants'

export const isOwner = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  try {
    const { id } = req.params
    const currentUserId = get(req, 'identity._id') as string

    if (!currentUserId) {
      return res.sendStatus(403)
    }

    if (currentUserId.toString() !== id) {
      return res.sendStatus(403)
    }

    next()
  } catch (error) {
    console.log(error)
    return res.sendStatus(400)
  }
}

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

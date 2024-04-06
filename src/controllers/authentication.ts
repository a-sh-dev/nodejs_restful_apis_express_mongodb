import { createUser, getUserByEmail } from '../db/users'
import { Request, Response } from 'express'
import { authentication, randomAuthString } from '../helpers/authentication'

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res
        .status(500)
        .json({ message: `Please provide 'email' and 'password` })
    }

    // !Must include the select chain to access the Hashed password
    const user = await getUserByEmail(email).select(
      '+authentication.salt +authentication.password',
    )

    if (!user) {
      return res.status(400).json({ message: `User '${email}' does not exist` })
    }

    const expectedHash = authentication(user.authentication.salt, password)
    if (user.authentication.password !== expectedHash) {
      return res.sendStatus(403)
    }

    const salt = randomAuthString()
    user.authentication.sessionToken = authentication(salt, user._id.toString())

    await user.save()

    res.cookie('LEARN-MDB-AUTH', user.authentication.sessionToken, {
      domain: 'localhost',
      path: '/',
    })

    return res.status(200).json(user).end()
  } catch (error) {
    console.log(error)
    return res.status(500).json({ message: error.message })
  }
}

export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, username } = req.body

    // Handle no input
    if (!email || !password || !username) {
      // return res.sendStatus(500)
      return res
        .status(500)
        .json({ message: `Please provide 'email', 'password' and 'username'` })
    }

    // Handle existing user
    const existingUser = await getUserByEmail(email)
    if (existingUser) {
      // return res.sendStatus(400)
      return res
        .status(500)
        .json({ message: `Existing user: ${existingUser} (${email}) exists` })
    }

    // Handle new user
    const salt = randomAuthString()
    const user = await createUser({
      email,
      username,
      authentication: {
        salt,
        password: authentication(salt, password),
      },
    })

    return res.status(200).json(user).end()
  } catch (error) {
    console.log(error.message)
    return res.status(500).json({ message: error.message })
  }
}

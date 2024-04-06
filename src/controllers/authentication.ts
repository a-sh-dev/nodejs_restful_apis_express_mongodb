import { createUser, getUserByEmail } from 'db/users'
import express from 'express'
import { authentication, randomAuthString } from 'helpers/authentication'

export const register = async (req: express.Request, res: express.Response) => {
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

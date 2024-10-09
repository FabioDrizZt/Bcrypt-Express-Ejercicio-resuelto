process.loadEnvFile()
const express = require('express')
const app = express()
const port = process.env.PORT || 3000

const bcryptjs = require('bcryptjs')
const saltRounds = parseInt(process.env.SALT_ROUNDS) || 12

app.use(express.json())

app.get('/', (req, res) => {
  res.json({ message: 'Bienvenid@s a la API de Bcryptjs.' })
})

app.post('/encriptar', async (req, res) => {
  try {
    const { password } = req.body

    if (!password || password.length <= 10) {
      return res.status(400).json({ message: 'Debe enviar una clave válida para encriptar (mayor a 10 caracteres).' })
    }

    const hashedPassword = await bcryptjs.hash(password, saltRounds)

    res.status(201).json({ message: 'Generación de hash exitosa', hashedPassword })
  } catch (error) {
    res.status(500).json({ message: 'Error al encriptar la contraseña' })
  }
})

app.post('/comparar', async (req, res) => {
  try {
    const { password, hash } = req.body

    if (!password || !hash) {
      return res.status(400).json({ message: 'Contraseña y hash son requeridos' })
    }

    const match = await bcryptjs.compare(password, hash)

    if (match) {
      return res.status(200).json({ message: 'Comparación exitosa', match })
    } else {
      return res.status(400).json({ message: 'No se ha podido validar la clave', match })
    }
  } catch (error) {
    res.status(500).json({ message: 'Error al comparar la contraseña con el hash' })
  }
})

app.listen(port, () => console.log(`Servidor escuchando en http://localhost:${port}`))

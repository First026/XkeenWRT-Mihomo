import { createRoot } from 'react-dom/client'

import App from './App.tsx'
import './globals.css'
import './lib/generator.js'

createRoot(document.getElementById('root')!).render(<App />)

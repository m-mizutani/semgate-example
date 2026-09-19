import { Routes, Route, Navigate } from 'react-router'
import Layout from './components/Layout'
import Home from './pages/Home'
import Hints from './pages/Hints'
import Login from './pages/Login'
import Ping from './pages/Ping'
import Files from './pages/Files'
import Greet from './pages/Greet'
import Fetch from './pages/Fetch'
import Track from './pages/Track'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Home />} />
        <Route path="/hints" element={<Hints />} />
        <Route path="/login" element={<Login />} />
        <Route path="/ping" element={<Ping />} />
        <Route path="/files" element={<Files />} />
        <Route path="/greet" element={<Greet />} />
        <Route path="/fetch" element={<Fetch />} />
        <Route path="/track" element={<Track />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

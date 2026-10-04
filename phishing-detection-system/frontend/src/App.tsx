import { Route, Routes } from 'react-router-dom'
import { PublicLayout } from './layouts/PublicLayout'
import { AppLayout } from './layouts/AppLayout'
import { Home } from './pages/Home'
import { Scanner } from './pages/Scanner'
import { ScanResult } from './pages/ScanResult'
import { HowItWorks } from './pages/HowItWorks'
import { Awareness } from './pages/Awareness'
import { AuthPage } from './pages/Auth'
import { Dashboard } from './pages/Dashboard'
import { History } from './pages/History'
import { Report } from './pages/Report'
import { Profile } from './pages/Profile'
import { Admin } from './pages/Admin'
import { NotFound } from './pages/NotFound'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AuthProvider } from './context/AuthContext'

export default function App() {
  return <AuthProvider><Routes>
    <Route element={<PublicLayout />}>
      <Route path="/" element={<Home />} />
      <Route path="/scanner" element={<Scanner />} />
      <Route path="/scan-result" element={<ScanResult />} />
      <Route path="/scan-result/:id" element={<ScanResult />} />
      <Route path="/how-it-works" element={<HowItWorks />} />
      <Route path="/awareness" element={<Awareness />} />
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/register" element={<AuthPage mode="register" />} />
    </Route>
    <Route element={<ProtectedRoute />}><Route element={<AppLayout />}>
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/history" element={<History />} />
      <Route path="/report" element={<Report />} />
      <Route path="/profile" element={<Profile />} />
    </Route></Route>
    <Route element={<ProtectedRoute role="ADMIN" />}><Route element={<AppLayout />}>
      <Route path="/admin" element={<Admin />} />
    </Route></Route>
    <Route path="*" element={<NotFound />} />
  </Routes></AuthProvider>
}

import { Outlet } from 'react-router-dom'
import { Footer } from '../components/Footer'
import { Navbar } from '../components/Navbar'
import { SkipLink } from '../components/SkipLink'

export function PublicLayout() {
  return <div className="min-h-screen bg-[#040a12]"><SkipLink/><Navbar /><main id="main-content"><Outlet /></main><Footer /></div>
}

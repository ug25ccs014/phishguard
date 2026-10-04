import { ButtonLink } from '../components/ui/Button'

export function NotFound() { return <div className="grid min-h-[70vh] place-items-center px-4"><div className="text-center"><div className="text-7xl font-bold text-white">404</div><h1 className="mt-4 text-2xl font-semibold text-white">Page not found</h1><p className="mt-2 text-sm text-slate-500">The requested security workspace page does not exist.</p><ButtonLink to="/" className="mt-6">Return home</ButtonLink></div></div> }

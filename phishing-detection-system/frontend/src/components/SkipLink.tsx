import { Link } from 'react-router-dom'

export function SkipLink() {
  return <Link to="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-sky-400 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-slate-950">Skip to main content</Link>
}

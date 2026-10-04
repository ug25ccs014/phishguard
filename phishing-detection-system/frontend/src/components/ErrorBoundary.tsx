import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Button } from './ui/Button'

type Props = { children: ReactNode }
type State = { failed: boolean }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false }

  static getDerivedStateFromError(): State { return { failed: true } }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('PhishGuard UI error', { message: error.message, componentStack: info.componentStack })
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <main className="grid min-h-screen place-items-center bg-[#040a12] px-6 py-16">
        <section className="panel w-full max-w-lg p-8 text-center">
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-amber-400/10 text-amber-300"><AlertTriangle size={22} /></div>
          <h1 className="mt-5 text-2xl font-bold text-white">Something went wrong</h1>
          <p className="mt-3 text-sm leading-6 text-slate-400">The security workspace hit an unexpected UI error. Reload the page to restore the application.</p>
          <Button className="mt-6" onClick={() => window.location.reload()}>Reload PhishGuard</Button>
        </section>
      </main>
    )
  }
}

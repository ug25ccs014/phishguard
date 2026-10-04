import axios, { AxiosError } from 'axios'
import type { AdminModelResponse, AdminOverviewResponse, AdminProvider, AuthUser, DashboardResponse, PhishingReport, ScanHistoryResponse, ScanResult } from '../types'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:4000/api/v1',
  timeout: 20_000,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

function getCookie(name: string): string | null {
  const entry = document.cookie.split('; ').find((part) => part.slice(0, part.indexOf('=')) === name)
  if (!entry) return null
  try { return decodeURIComponent(entry.slice(name.length + 1)) } catch { return null }
}

api.interceptors.request.use((config) => {
  const method = (config.method ?? 'get').toLowerCase()
  if (!['get', 'head', 'options'].includes(method)) {
    const csrf = getCookie(import.meta.env.VITE_CSRF_COOKIE_NAME ?? 'phishguard_csrf')
    if (csrf) config.headers['x-csrf-token'] = csrf
  }
  return config
})

export function apiErrorMessage(error: unknown, fallback = 'The request could not be completed.') {
  if (error instanceof AxiosError) {
    const apiMessage = error.response?.data?.error?.message
    if (typeof apiMessage === 'string') return apiMessage
    if (error.code === 'ECONNABORTED' || error.message.includes('Network Error')) return 'The PhishGuard API is unavailable. Start the backend and try again.'
  }
  return fallback
}

export async function getHealth() {
  const response = await api.get('/health')
  return response.data
}

export async function ensureCsrfToken(): Promise<void> { await api.get('/auth/csrf') }

export async function scanUrl(url: string): Promise<ScanResult> {
  const response = await api.post<ScanResult>('/scans', { url })
  return response.data
}

export async function registerUser(input: { name: string; email: string; password: string }): Promise<AuthUser> {
  await ensureCsrfToken()
  const response = await api.post<{ user: AuthUser }>('/auth/register', input)
  return response.data.user
}

export async function loginUser(input: { email: string; password: string }): Promise<AuthUser> {
  await ensureCsrfToken()
  const response = await api.post<{ user: AuthUser }>('/auth/login', input)
  return response.data.user
}

export async function logoutUser(): Promise<void> { await api.post('/auth/logout') }

export async function getCurrentUser(): Promise<AuthUser> {
  const response = await api.get<{ user: AuthUser }>('/auth/me')
  return response.data.user
}

export async function updateProfile(input: { name: string; highRiskAlerts: boolean; weeklySummary: boolean }): Promise<AuthUser> {
  const response = await api.patch<{ user: AuthUser }>('/auth/profile', input)
  return response.data.user
}

export async function changePassword(input: { currentPassword: string; newPassword: string }): Promise<void> {
  await api.patch('/auth/password', input)
}

export async function getDashboard(): Promise<DashboardResponse> {
  const response = await api.get<DashboardResponse>('/dashboard')
  return response.data
}

export async function getScanHistory(params: { page?: number; pageSize?: number; search?: string; verdict?: string } = {}): Promise<ScanHistoryResponse> {
  const response = await api.get<ScanHistoryResponse>('/scans', { params })
  return response.data
}

export async function getStoredScan(id: string): Promise<ScanResult> {
  const response = await api.get<ScanResult>(`/scans/${encodeURIComponent(id)}`)
  return response.data
}

export async function deleteStoredScan(id: string): Promise<void> { await api.delete(`/scans/${encodeURIComponent(id)}`) }

export async function createReport(input: { url: string; category: string; description?: string }): Promise<{ id: string; status: string; createdAt: string }> {
  const response = await api.post('/reports', input)
  return response.data
}

export async function getMyReports(): Promise<{ items: PhishingReport[] }> {
  const response = await api.get('/reports')
  return response.data
}

export async function getAdminOverview(): Promise<AdminOverviewResponse> {
  const response = await api.get<AdminOverviewResponse>('/admin/overview')
  return response.data
}

export async function getAdminReports(params: { status?: string; search?: string } = {}): Promise<{ items: PhishingReport[] }> {
  const response = await api.get<{ items: PhishingReport[] }>('/admin/reports', { params })
  return response.data
}

export async function updateAdminReport(id: string, input: { status: string; reviewNote?: string }): Promise<PhishingReport> {
  const response = await api.patch<{ report: PhishingReport }>(`/admin/reports/${encodeURIComponent(id)}`, input)
  return response.data.report
}

export async function getAdminProviders(): Promise<{ providers: AdminProvider[] }> {
  const response = await api.get('/admin/providers')
  return response.data
}

export async function getAdminModel(): Promise<AdminModelResponse> {
  const response = await api.get<AdminModelResponse>('/admin/model')
  return response.data
}

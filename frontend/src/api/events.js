import api from './index'
import { normalizeEventList, normalizeIncidentDetail, normalizeIncidentList, unwrapAPIEnvelope } from './adapters'

export const incidentsAPI = {
  list: async (params) => normalizeIncidentList(await api.get('/incidents', { params })),
  detail: async (id) => normalizeIncidentDetail(await api.get(`/incidents/${id}`)),
  timeline: async (id, params) => normalizeEventList(await api.get(`/timeline/${id}`, { params })),
  updateStatus: async (id, status) => unwrapAPIEnvelope(await api.put(`/incidents/${id}/status`, { status }))
}

export const timelineAPI = {
  list: async (params) => normalizeEventList(await api.get('/timeline', { params })),
  detail: async (id, params) => normalizeEventList(await api.get(`/timeline/${id}`, { params }))
}

export const statsAPI = {
  dashboard: async () => unwrapAPIEnvelope(await api.get('/stats'))
}

import api from './index'
import { normalizeEventDetail, normalizeEventList, normalizeIncidentDetail, normalizeIncidentList, unwrapAPIEnvelope } from './adapters'

export const eventsAPI = {
  list: async (params) => normalizeEventList(await api.get('/events', { params })),
  detail: async (id) => normalizeEventDetail(await api.get(`/events/${id}`)),
  search: async (params) => normalizeEventList(await api.post('/events/search', params)),
  updateStatus: async (id, status) => unwrapAPIEnvelope(await api.put(`/events/${id}/status`, { status }))
}

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

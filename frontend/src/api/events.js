import api from './index'
import { normalizeEventList, normalizeIncidentDetail, normalizeIncidentList, unwrapAPIEnvelope } from './adapters'

export const incidentsAPI = {
  list: async (params) => normalizeIncidentList(await api.get('/incidents', { params })),
  detail: async (id) => normalizeIncidentDetail(await api.get(`/incidents/${id}`)),
  timeline: async (id, params) => normalizeEventList(await api.get(`/timeline/${id}`, { params })),
  updateStatus: async (id, status, options = {}) => unwrapAPIEnvelope(await api.put(`/incidents/${id}/status`, { status, ...options })),
  assign: async (id, assignee) => unwrapAPIEnvelope(await api.put(`/incidents/${id}/assign`, { assignee })),
  notes: async (id) => unwrapAPIEnvelope(await api.get(`/incidents/${id}/notes`)),
  addNote: async (id, body) => unwrapAPIEnvelope(await api.post(`/incidents/${id}/notes`, { body }))
}

export const timelineAPI = {
  list: async (params) => normalizeEventList(await api.get('/timeline', { params })),
  detail: async (id, params) => normalizeEventList(await api.get(`/timeline/${id}`, { params }))
}

export const statsAPI = {
  dashboard: async () => unwrapAPIEnvelope(await api.get('/stats'))
}

export const responseAPI = {
  list: async () => unwrapAPIEnvelope(await api.get('/response/actions')),
  create: async (payload) => unwrapAPIEnvelope(await api.post('/response/actions', payload)),
  approve: async (id) => unwrapAPIEnvelope(await api.post(`/response/actions/${id}/approve`)),
  rollback: async (id) => unwrapAPIEnvelope(await api.post(`/response/actions/${id}/rollback`)),
}

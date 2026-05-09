import api from './index'

export const eventsAPI = {
  list: (params) => api.get('/events', { params }),
  detail: (id) => api.get(`/events/${id}`),
  search: (params) => api.post('/events/search', params),
  updateStatus: (id, status) => api.put(`/events/${id}/status`, { status })
}

export const statsAPI = {
  dashboard: () => api.get('/stats')
}

import api from './index'

export const eventsV2Client = Object.freeze({
  list: (params = {}) => api.get('/v2/events', { params }),
  detail: (eventUID) => api.get(`/v2/events/${encodeURIComponent(eventUID)}`),
})

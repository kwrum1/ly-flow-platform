import { apiV2 } from './index'

export const eventsV2Client = Object.freeze({
  list: (params = {}) => apiV2.get('/events', { params }),
  detail: (eventUID) => apiV2.get(`/events/${encodeURIComponent(eventUID)}`),
})

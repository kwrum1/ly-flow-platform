import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { describe, expect, it } from 'vitest'
import RealtimeStatus from './RealtimeStatus.vue'
import { CONNECTION_STATUS } from '../realtime'

async function renderStatus(status) {
  const app = createSSRApp({
    render: () => h(RealtimeStatus, { status }),
  })
  return renderToString(app)
}

describe('RealtimeStatus', () => {
  it('renders open state as success status', async () => {
    const html = await renderStatus(CONNECTION_STATUS.OPEN)
    expect(html).toContain('data-testid="realtime-status"')
    expect(html).toContain('实时连接正常')
    expect(html).toContain('success')
  })

  it('renders degraded state with warning style', async () => {
    const html = await renderStatus(CONNECTION_STATUS.DEGRADED)
    expect(html).toContain('实时降级轮询')
    expect(html).toContain('warning')
  })

  it('falls back to idle state for unknown status', async () => {
    const html = await renderStatus('unknown')
    expect(html).toContain('实时连接空闲')
    expect(html).toContain('muted')
  })
})

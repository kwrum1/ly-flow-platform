import { productIdentity } from '../contracts/backend-contracts'

const dateTimeFormatter = new Intl.DateTimeFormat(productIdentity.locale, {
  timeZone: productIdentity.timeZone,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

const timeFormatter = new Intl.DateTimeFormat(productIdentity.locale, {
  timeZone: productIdentity.timeZone,
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

export function formatChinaDateTime(value) {
  if (!value) return '暂无时间'
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '时间格式异常'
  return dateTimeFormatter.format(date)
}

export function formatChinaTime(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '时间格式异常'
  return timeFormatter.format(date)
}

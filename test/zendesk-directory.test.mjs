import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskClient } from '../dist/zendesk-client.js'

function directoryClient(bodies) {
  const requests = []
  return {
    requests,
    client: new ZendeskClient({
      subdomain: 'acme',
      auth: {
        kind: 'oauth',
        accessToken: 'access-token-sentinel',
        onUnauthorized: async () => assert.fail('fresh token must not refresh'),
      },
      fetch: async (input) => {
        requests.push(String(input))
        const body = bodies.shift()
        assert.notEqual(body, undefined, 'unexpected Zendesk request')
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      },
    }),
  }
}

test('directory methods retrieve exact records and cursor-paginated ticket history', async () => {
  const { client, requests } = directoryClient([
    { user: { id: 101, name: 'Requester', email: 'requester@example.test', user_fields: { tier: 'gold' } } },
    { organization: { id: 202, name: 'Acme', domain_names: ['example.test'], organization_fields: { region: 'eu' } } },
    { tickets: [{ id: 301, requester_id: 101, group_id: 73 }], meta: { has_more: false }, links: { next: null } },
    { tickets: [{ id: 302, requester_id: 101, assignee_id: 101 }], meta: { has_more: false }, links: { next: null } },
    { tickets: [{ id: 303, organization_id: 202, custom_status_id: 76 }], meta: { has_more: false }, links: { next: null } },
  ])

  const user = await client.getUser(101)
  const organization = await client.getOrganization(202)
  const requested = await client.listUserTickets(101, 'requested', { pageSize: 25 })
  const assigned = await client.listUserTickets(101, 'assigned', { pageSize: 25 })
  const organizationTickets = await client.listOrganizationTickets(202, { pageSize: 25 })

  assert.deepEqual(requests, [
    'https://acme.zendesk.com/api/v2/users/101.json',
    'https://acme.zendesk.com/api/v2/organizations/202.json',
    'https://acme.zendesk.com/api/v2/users/101/tickets/requested.json?page%5Bsize%5D=25',
    'https://acme.zendesk.com/api/v2/users/101/tickets/assigned.json?page%5Bsize%5D=25',
    'https://acme.zendesk.com/api/v2/organizations/202/tickets.json?page%5Bsize%5D=25',
  ])
  assert.deepEqual(user.user_fields, { tier: 'gold' })
  assert.deepEqual(organization.domain_names, ['example.test'])
  assert.equal(requested.items[0].group_id, 73)
  assert.equal(assigned.items[0].assignee_id, 101)
  assert.equal(organizationTickets.items[0].custom_status_id, 76)
})

test('all supported user ticket relationships map to fixed paths', async () => {
  const { client, requests } = directoryClient([
    { tickets: [], meta: { has_more: false }, links: { next: null } },
    { tickets: [], meta: { has_more: false }, links: { next: null } },
  ])

  await client.listUserTickets(101, 'ccd', { pageSize: 10 })
  await client.listUserTickets(101, 'followed', { pageSize: 10 })

  assert.equal(new URL(requests[0]).pathname, '/api/v2/users/101/tickets/ccd.json')
  assert.equal(new URL(requests[1]).pathname, '/api/v2/users/101/tickets/followed.json')
})

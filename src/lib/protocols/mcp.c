/*
 * mcp.c
 *
 * Copyright (C) 2026 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MCP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* MCP (Model Context Protocol) - JSON-RPC 2.0 based protocol for AI context communication
   Transport: HTTP POST to /mcp endpoint, with SSE streaming responses
   Key signatures:
   - Mcp-Session-Id header (unique to MCP)
   - JSON body with "protocolVersion" field
   - MCP method names: initialize, tools/list, tools/call, resources/list, prompts/list */

static const char *mcp_methods[] = {
  "initialize",
  "tools/list",
  "tools/call",
  "resources/list",
  "resources/read",
  "prompts/list",
  "prompts/get",
  "notifications/initialized",
  "notifications/cancelled",
  "notifications/progress",
  "notifications/message",
  NULL
};

static int mcp_check_method(const u_int8_t *payload, u_int16_t payload_len) {
  const char *jsonrpc = ndpi_strnstr((const char *)payload, "\"jsonrpc\"", payload_len);
  const char *method_prefix = ndpi_strnstr((const char *)payload, "\"method\"", payload_len);

  if(jsonrpc == NULL || method_prefix == NULL)
    return 0;

  /* Find the method value after "method" key */
  const char *colon = ndpi_strnstr(method_prefix, ":\"", payload_len - (method_prefix - (const char *)payload));
  if(colon == NULL)
    return 0;

  const char *value_start = colon + 2; /* skip :\" */

  int i;
  for(i = 0; mcp_methods[i] != NULL; i++) {
    size_t mlen = strlen(mcp_methods[i]);
    if((const char *)payload + payload_len - value_start >= mlen &&
       strncmp(value_start, mcp_methods[i], mlen) == 0 &&
       value_start[mlen] == '\"')
      return 1;
  }

  /* Also check for protocolVersion field (unique to MCP initialize) */
  if(ndpi_strnstr((const char *)payload, "\"protocolVersion\"", payload_len) != NULL &&
     ndpi_strnstr((const char *)payload, "\"jsonrpc\"", payload_len) != NULL)
    return 1;

  return 0;
}

static void ndpi_search_mcp(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const char *payload_str = (const char *)packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;

  NDPI_LOG_DBG(ndpi_struct, "search MCP\n");

  /* Helper: extract MCP method name and optional tool_name from JSON body */
  if(payload_len > 30 && payload_str[0] == '{') {
    const char *method_start = NULL;
    const char *tool_call = ndpi_strnstr(payload_str, "\"method\":\"tools/call\"", payload_len);

    if(tool_call)
      method_start = "tools/call";
    else {
      int i;
      for(i = 0; mcp_methods[i] != NULL; i++) {
        const char *pos = ndpi_strnstr(payload_str, mcp_methods[i], payload_len);
        if(pos != NULL) {
          /* Verify it's inside "method":"..." */
          const char *m = ndpi_strnstr(payload_str, "\"method\"", payload_len);
          if(m != NULL) {
            const char *colon = ndpi_strnstr(m, ":\"", payload_len - (m - payload_str));
            if(colon != NULL) {
              const char *vs = colon + 2;
              size_t mlen = strlen(mcp_methods[i]);
              if((payload_str + payload_len - vs >= (int)mlen) &&
                 strncmp(vs, mcp_methods[i], mlen) == 0 &&
                 vs[mlen] == '\"') {
                method_start = mcp_methods[i];
                break;
              }
            }
          }
        }
      }
    }

    if(method_start) {
      size_t mlen = strlen(method_start);
      if(mlen < sizeof(flow->protos.mcp.method)) {
        memcpy(flow->protos.mcp.method, method_start, mlen);
        flow->protos.mcp.method[mlen] = '\0';
      }

      /* If tools/call, try to extract tool name: "params":{"name":"read_file"... */
      if(strcmp(method_start, "tools/call") == 0) {
        const char *name = ndpi_strnstr(payload_str, "\"name\":\"", payload_len);
        if(name != NULL) {
          const char *tv = name + 8; /* skip "name":" */
          const char *te = ndpi_strnstr(tv, "\"", payload_len - (tv - payload_str));
          if(te != NULL) {
            size_t tlen = te - tv;
            if(tlen < sizeof(flow->protos.mcp.tool_name)) {
              memcpy(flow->protos.mcp.tool_name, tv, tlen);
              flow->protos.mcp.tool_name[tlen] = '\0';
            }
          }
        }
      }

      /* Extract protocolVersion if present */
      const char *pv = ndpi_strnstr(payload_str, "\"protocolVersion\":\"", payload_len);
      if(pv != NULL) {
        const char *pvv = pv + 20;
        const char *pve = ndpi_strnstr(pvv, "\"", payload_len - (pvv - payload_str));
        if(pve != NULL) {
          size_t plen = pve - pvv;
          if(plen < sizeof(flow->protos.mcp.protocol_version)) {
            memcpy(flow->protos.mcp.protocol_version, pvv, plen);
            flow->protos.mcp.protocol_version[plen] = '\0';
          }
        }
      }
    }
  }

  /* Case 1: MCP over HTTP (Streamable HTTP transport) */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check for Mcp-Session-Id header - most reliable MCP signature */
    if(packet->payload_packet_len > 0 &&
       ndpi_strnstr(payload_str, "Mcp-Session-Id",
                    payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found MCP (Mcp-Session-Id header)\n");

      /* Extract session ID value */
      const char *sid = ndpi_strnstr(payload_str, "Mcp-Session-Id", payload_len);
      if(sid != NULL) {
        const char *colon = ndpi_strnstr(sid, ": ", payload_len - (sid - payload_str));
        if(colon != NULL) {
          const char *sv = colon + 2;
          const char *se = ndpi_strnstr(sv, "\r\n", payload_len - (sv - payload_str));
          if(se != NULL) {
            size_t slen = se - sv;
            if(slen < sizeof(flow->protos.mcp.session_id)) {
              memcpy(flow->protos.mcp.session_id, sv, slen);
              flow->protos.mcp.session_id[slen] = '\0';
            }
          }
        }
      }

      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MCP,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check for /mcp URL path with JSON content */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0) {
      if(LINE_ENDS(packet->http_url_name, "/mcp") ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/mcp",
                     packet->http_url_name.len) != NULL) {

        /* Verify JSON content type */
        if((packet->content_line.ptr != NULL &&
            LINE_ENDS(packet->content_line, "application/json")) ||
           (payload_len > 0 &&
            packet->payload[0] == '{')) {
          NDPI_LOG_INFO(ndpi_struct, "found MCP (/mcp URL path)\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MCP,
                                     NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
          return;
        }
      }
    }

    /* Check HTTP payload for MCP method + jsonrpc */
    if(payload_len > 30 && packet->payload[0] == '{') {
      if(mcp_check_method(packet->payload, payload_len)) {
        NDPI_LOG_INFO(ndpi_struct, "found MCP (method match in HTTP)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MCP,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: MCP over raw TCP (cleartext without prior HTTP detection) */
  if(packet->tcp != NULL && payload_len > 30 && packet->payload[0] == '{') {
    if(mcp_check_method(packet->payload, payload_len)) {
      NDPI_LOG_INFO(ndpi_struct, "found MCP (raw TCP)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MCP,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_mcp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("MCP", ndpi_struct,
                     ndpi_search_mcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_MCP);
}
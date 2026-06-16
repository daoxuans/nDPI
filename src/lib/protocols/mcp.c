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

static int mcp_extract_json_string_value(const char *payload, u_int16_t payload_len,
                                         const char *key,
                                         char *out, size_t out_len) {
  char key_buf[48];
  size_t key_len = strlen(key);
  const char *kpos, *vstart, *vend;

  if(out_len == 0 || key_len == 0 || key_len > (sizeof(key_buf) - 3))
    return 0;

  key_buf[0] = '"';
  memcpy(&key_buf[1], key, key_len);
  key_buf[key_len + 1] = '"';
  key_buf[key_len + 2] = '\0';

  kpos = ndpi_strnstr(payload, key_buf, payload_len);
  if(kpos == NULL)
    return 0;

  vstart = kpos + key_len + 2; /* skip "key" */
  while((const char *)payload + payload_len > vstart &&
        (*vstart == ' ' || *vstart == '\t' || *vstart == '\r' || *vstart == '\n'))
    vstart++;

  if((const char *)payload + payload_len <= vstart || *vstart != ':')
    return 0;

  vstart++;
  while((const char *)payload + payload_len > vstart &&
        (*vstart == ' ' || *vstart == '\t' || *vstart == '\r' || *vstart == '\n'))
    vstart++;

  if((const char *)payload + payload_len <= vstart || *vstart != '"')
    return 0;

  vstart++; /* skip opening quote */
  vend = ndpi_strnstr(vstart, "\"", payload_len - (vstart - payload));
  if(vend == NULL || vend <= vstart)
    return 0;

  if((size_t)(vend - vstart) >= out_len)
    return 0;

  memcpy(out, vstart, vend - vstart);
  out[vend - vstart] = '\0';

  return 1;
}

static int mcp_extract_header_value_ci(const char *payload, u_int16_t payload_len,
                                       const char *header,
                                       char *out, size_t out_len) {
  const char *hpos, *line_end, *colon, *vstart, *vend;

  if(out_len == 0)
    return 0;

  hpos = ndpi_strncasestr(payload, header, payload_len);
  if(hpos == NULL)
    return 0;

  line_end = ndpi_strnstr(hpos, "\n", payload_len - (hpos - payload));
  if(line_end == NULL)
    line_end = payload + payload_len;

  colon = ndpi_strnstr(hpos, ":", line_end - hpos);
  if(colon == NULL)
    return 0;

  vstart = colon + 1;
  while(vstart < line_end && (*vstart == ' ' || *vstart == '\t'))
    vstart++;

  vend = line_end;
  if(vend > vstart && *(vend - 1) == '\r')
    vend--;

  if(vend <= vstart || (size_t)(vend - vstart) >= out_len)
    return 0;

  memcpy(out, vstart, vend - vstart);
  out[vend - vstart] = '\0';

  return 1;
}

static int mcp_check_method(const u_int8_t *payload, u_int16_t payload_len) {
  const char *jsonrpc = ndpi_strnstr((const char *)payload, "\"jsonrpc\"", payload_len);
  char method[48];
  int method_found;

  if(jsonrpc == NULL)
    return 0;

  method_found = mcp_extract_json_string_value((const char *)payload, payload_len,
                                               "method", method, sizeof(method));

  int i;
  if(method_found) {
    for(i = 0; mcp_methods[i] != NULL; i++) {
      if(strcmp(method, mcp_methods[i]) == 0)
        return 1;
    }
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
    if(mcp_extract_json_string_value(payload_str, payload_len,
                                     "method", flow->protos.mcp.method,
                                     sizeof(flow->protos.mcp.method))) {

      /* If tools/call, try to extract tool name: "params":{"name":"read_file"... */
      if(strcmp(flow->protos.mcp.method, "tools/call") == 0) {
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
      mcp_extract_json_string_value(payload_str, payload_len,
                                    "protocolVersion",
                                    flow->protos.mcp.protocol_version,
                                    sizeof(flow->protos.mcp.protocol_version));
    }
  }

  /* Case 1: MCP over HTTP (Streamable HTTP transport) */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check for Mcp-Session-Id header - most reliable MCP signature */
    if(packet->payload_packet_len > 0 &&
       ndpi_strncasestr(payload_str, "mcp-session-id",
                    payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found MCP (Mcp-Session-Id header)\n");

      /* Extract session ID value */
      mcp_extract_header_value_ci(payload_str, payload_len,
                                  "mcp-session-id",
                                  flow->protos.mcp.session_id,
                                  sizeof(flow->protos.mcp.session_id));

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
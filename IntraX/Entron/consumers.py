import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from Entron.models import Company

class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        company_id = await self._resolve_company_id()

        if company_id is None:
            await self.close()
            return

        self.company_group_name = f"company_{company_id}"
        await self.channel_layer.group_add(self.company_group_name, self.channel_name)
        await self.accept()

    async def _resolve_company_id(self):
        user = self.scope.get("user")
        if user is not None and user.is_authenticated and getattr(user, "company_id", None):
            return str(user.company_id)
        session = self.scope.get("session")
        if session is not None:
            session_company_id = session.get("company_id")
            if session_company_id and await self._company_exists(session_company_id):
                return str(session_company_id)
        return None

    @database_sync_to_async
    def _company_exists(self, company_id):
        return Company.objects.filter(id=company_id).exists()

    async def disconnect(self, close_code):
        if hasattr(self, "company_group_name"):
            await self.channel_layer.group_discard(self.company_group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        pass

    async def alert_new(self, event):
        await self.send(text_data=json.dumps({
            "type": "alert.new",
            "alert": event["alert"],
        }))

    async def device_status(self, event):
        await self.send(text_data=json.dumps({
            "type": "device.status",
            "device": event["device"],
        }))
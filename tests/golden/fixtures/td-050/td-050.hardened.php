<?php

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Stripe\Webhook;

class WebhookController
{
    #[Route('/webhook/stripe', methods: ['POST'])]
    public function stripeWebhook(Request $request): Response
    {
        $event = Webhook::constructEvent(
            $request->getContent(),
            $request->headers->get('Stripe-Signature'),
            $webhookSecret
        );
        return new Response('ok');
    }

    #[Route('/webhook/paypal', methods: ['POST'])]
    public function paypalWebhook(Request $request): Response
    {
        verifyWebhookSignature($request->getContent());
        $event = json_decode($request->getContent(), true);
        return new Response('ok');
    }
}

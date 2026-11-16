<?php

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class WebhookController
{
    #[Route('/webhook/stripe', methods: ['POST'])]
    public function stripeWebhook(Request $request): Response
    {
        $event = json_decode($request->getContent(), true);
        // Acts on $event without verifying the signature — forgeable.
        return new Response('ok');
    }

    #[Route('/webhook/paypal', methods: ['POST'])]
    public function paypalWebhook(Request $request): Response
    {
        $event = $request->toArray();
        return new Response('ok');
    }
}
